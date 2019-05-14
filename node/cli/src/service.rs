// Copyright 2018 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

#![warn(unused_extern_crates)]

//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

use std::sync::Arc;
use std::time::Duration;

use client;
use consensus::{import_queue, start_aura, AuraImportQueue, SlotDuration, NothingExtra};
use grandpa;
use node_executor;
use primitives::ed25519::Pair;
use node_primitives::Block;
use node_runtime::{GenesisConfig, RuntimeApi};
use substrate_service::{
	FactoryFullConfiguration, LightComponents, FullComponents, FullBackend,
	FullClient, LightClient, LightBackend, FullExecutor, LightExecutor, TaskExecutor,
};
use transaction_pool::{self, txpool::{Pool as TransactionPool}};
use inherents::InherentDataProviders;
use network::construct_simple_protocol;
use substrate_service::construct_service_factory;
use log::info;

construct_simple_protocol! {
	/// Demo protocol attachment for substrate.
	pub struct NodeProtocol where Block = Block { }
}

/// Node specific configuration
pub struct NodeConfig<F: substrate_service::ServiceFactory> {
	/// grandpa connection to import block
	// FIXME #1134 rather than putting this on the config, let's have an actual intermediate setup state
	pub grandpa_import_setup: Option<(Arc<grandpa::BlockImportForService<F>>, grandpa::LinkHalfForService<F>)>,
	inherent_data_providers: InherentDataProviders,
}

impl<F> Default for NodeConfig<F> where F: substrate_service::ServiceFactory {
	fn default() -> NodeConfig<F> {
		NodeConfig {
			grandpa_import_setup: None,
			inherent_data_providers: InherentDataProviders::new(),
		}
	}
}

construct_service_factory! {
	struct Factory {
		Block = Block,
		RuntimeApi = RuntimeApi,
		NetworkProtocol = NodeProtocol { |config| Ok(NodeProtocol::new()) },
		RuntimeDispatch = node_executor::Executor,
		FullTransactionPoolApi = transaction_pool::ChainApi<client::Client<FullBackend<Self>, FullExecutor<Self>, Block, RuntimeApi>, Block>
			{ |config, client| Ok(TransactionPool::new(config, transaction_pool::ChainApi::new(client))) },
		LightTransactionPoolApi = transaction_pool::ChainApi<client::Client<LightBackend<Self>, LightExecutor<Self>, Block, RuntimeApi>, Block>
			{ |config, client| Ok(TransactionPool::new(config, transaction_pool::ChainApi::new(client))) },
		Genesis = GenesisConfig,
		Configuration = NodeConfig<Self>,
		FullService = FullComponents<Self>
			{ |config: FactoryFullConfiguration<Self>, executor: TaskExecutor|
				FullComponents::<Factory>::new(config, executor) },
		AuthoritySetup = {
			|mut service: Self::FullService, executor: TaskExecutor, local_key: Option<Arc<Pair>>| {
				let (block_import, link_half) = service.config.custom.grandpa_import_setup.take()
					.expect("Link Half and Block Import are present for Full Services or setup failed before. qed");

				if let Some(ref key) = local_key {
					info!("Using authority key {}", key.public());
					let proposer = Arc::new(substrate_basic_authorship::ProposerFactory {
						client: service.client(),
						transaction_pool: service.transaction_pool(),
					});

					let client = service.client();
					executor.spawn(start_aura(
						SlotDuration::get_or_compute(&*client)?,
						key.clone(),
						client,
						block_import.clone(),
						proposer,
						service.network(),
						service.on_exit(),
						service.config.custom.inherent_data_providers.clone(),
					)?);

					info!("Running Grandpa session as Authority {}", key.public());
				}

				executor.spawn(grandpa::run_grandpa(
					grandpa::Config {
						local_key,
						// FIXME #1578 make this available through chainspec
						gossip_duration: Duration::new(4, 0),
						justification_period: 4096,
						name: Some(service.config.name.clone())
					},
					link_half,
					grandpa::NetworkBridge::new(service.network()),
					service.on_exit(),
				)?);

				Ok(service)
			}
		},
		LightService = LightComponents<Self>
			{ |config, executor| <LightComponents<Factory>>::new(config, executor) },
		FullImportQueue = AuraImportQueue<
			Self::Block,
			FullClient<Self>,
			NothingExtra,
		>
			{ |config: &mut FactoryFullConfiguration<Self>, client: Arc<FullClient<Self>>| {
				let slot_duration = SlotDuration::get_or_compute(&*client)?;
				let (block_import, link_half) =
					grandpa::block_import::<_, _, _, RuntimeApi, FullClient<Self>>(
						client.clone(), client.clone()
					)?;
				let block_import = Arc::new(block_import);
				let justification_import = block_import.clone();

				config.custom.grandpa_import_setup = Some((block_import.clone(), link_half));

				import_queue(
					slot_duration,
					block_import,
					Some(justification_import),
					client,
					NothingExtra,
					config.custom.inherent_data_providers.clone(),
				).map_err(Into::into)
			}},
		LightImportQueue = AuraImportQueue<
			Self::Block,
			LightClient<Self>,
			NothingExtra,
		>
			{ |config: &FactoryFullConfiguration<Self>, client: Arc<LightClient<Self>>| {
					import_queue(
						SlotDuration::get_or_compute(&*client)?,
						client.clone(),
						None,
						client,
						NothingExtra,
						config.custom.inherent_data_providers.clone(),
					).map_err(Into::into)
				}
			},
	}
}


#[cfg(test)]
mod tests {
	#[test]
	fn test_sync() {
		use std::sync::Arc;
		use super::Factory;
		use crate::chain_spec;
		use parity_codec::{Encode, Decode};
		use consensus::{BlockOrigin, ImportBlock, Environment, Proposer,
			ForkChoiceStrategy, AuraConsensusData, CompatibleDigestItem};
		use primitives::ed25519;
		use node_primitives::{BlockId, OpaqueExtrinsic, DigestItem, Block};
		use node_runtime::{Call, Address, BalancesCall, Era, UncheckedExtrinsic};
		use sr_primitives::traits::{Block as BlockT, BlockNumberToHash};
		use keyring::Keyring;
		use substrate_service as service;

		let alice: Arc<ed25519::Pair> = Arc::new(Keyring::Alice.into());
		let bob: Arc<ed25519::Pair> = Arc::new(Keyring::Bob.into());
		let validators = vec![alice.public().0.into(), bob.public().0.into()];
		let keys: Vec<&ed25519::Pair> = vec![&*alice, &*bob];
		let mut slot_num = 1;
		let block_factory = |service: &<Factory as service::ServiceFactory>::FullService| {
			let block_id = BlockId::number(service.client().info().unwrap().chain.best_number);
			let parent_header = service.client().header(&block_id).unwrap().unwrap();
			let proposer_factory = Arc::new(substrate_basic_authorship::ProposerFactory {
				client: service.client(),
				transaction_pool: service.transaction_pool(),
			});
			let consensus_data = AuraConsensusData {
				timestamp: slot_num * 2,
				slot: slot_num,
				slot_duration: 2,
			};
			let proposer = <Environment<Block, AuraConsensusData, Error=_, Proposer=_>>::init(&*proposer_factory, &parent_header, &validators).unwrap();
			let block = proposer.propose(consensus_data).expect("Error making test block");
			let (header, body) = block.deconstruct();
			let pre_hash = header.hash();
			let parent_hash = header.parent_hash.clone();
			// sign the pre-sealed hash of the block and then
			// add it to a digest item.
			let to_sign = (slot_num, pre_hash).encode();
			let authority_index = (slot_num as usize) % keys.len();
			let signature = keys[authority_index].sign(&to_sign[..]);
			let item = <DigestItem as CompatibleDigestItem>::aura_seal(
				slot_num,
				signature,
			);
			slot_num += 1;
			ImportBlock {
				origin: BlockOrigin::File,
				justification: None,
				post_digests: vec![item],
				finalized: true,
				body: Some(body),
				header: header,
				auxiliary: Vec::new(),
				fork_choice: ForkChoiceStrategy::LongestChain,
			}
		};
		let extrinsic_factory = |service: &<Factory as service::ServiceFactory>::FullService| {
			let payload = (0.into(), Call::Balances(BalancesCall::transfer(Address::Id(bob.public().0.into()), 69.into())), Era::immortal(), service.client().genesis_hash());
			let signature = alice.sign(&payload.encode()).into();
			let id = alice.public().0.into();
			let xt = UncheckedExtrinsic {
				signature: Some((RawAddress::Id(id), signature, payload.0, Era::immortal())),
				function: payload.1,
			}.encode();
			let v: Vec<u8> = Decode::decode(&mut xt.as_slice()).unwrap();
			OpaqueExtrinsic(v)
		};
		service_test::sync::<Factory, _, _>(chain_spec::tests::integration_test_config(), block_factory, extrinsic_factory);
	}

}
