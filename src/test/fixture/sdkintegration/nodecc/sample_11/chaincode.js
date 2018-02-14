/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// This is a node-js version of example_02.go

const shim = require('fabric-shim');

// An log4js logger instance
var logger = shim.newLogger('example_cc0');
// The logger level can also be set by environment variable 'CORE_CHAINCODE_LOGGING_SHIM'
// to CRITICAL, ERROR, WARNING, DEBUG
logger.level = 'info';

var Chaincode = class {
	async Init(stub) {
		logger.info('########### example_cc0 Init ###########');
		let ret = stub.getFunctionAndParameters();

		let A, B;    // Entities
		let Aval, Bval; // Asset holdings
		let args = ret.params;

		if (args.length === 0) {
			try {
				return shim.success();
			} catch (e) {
				return shim.error(e);
			}
		}

		if (args.length === 4) {
			A = args[0];
			B = args[2];

			Aval = parseInt(args[1]);
			if (isNaN(Aval)) {
				return shim.error('Expecting integer value for asset holding');
			}
			Bval = parseInt(args[3]);
			if (isNaN(Bval)) {
				return shim.error('Expecting integer value for asset holding');
			}

			logger.info(`Aval = ${Aval}, Bval = ${Bval}`);

			try {
				// Write the state to the ledger
				await stub.putState(A, Buffer.from(Aval.toString()));
				await stub.putState(B, Buffer.from(Bval.toString()));
				return shim.success();
			} catch (e) {
				return shim.error(e);
			}
		} else {
			return shim.error('init expects 4 args');
		}
	}

	async Invoke(stub) {
		logger.info('########### example_cc0 Invoke ###########');
		let ret = stub.getFunctionAndParameters();
		let fcn = ret.fcn;
		let args = ret.params;

		logger.info('Invoke fcn' + fcn);

		if (fcn === 'delete') {
			return this.delete(stub, args);
		}

		if (fcn === 'query') {
			return this.query(stub, args);
		}

		if (fcn === 'move') {
			return this.move(stub, args);
		}

		logger.Errorf(`Unknown action, check the first argument, must be one of 'delete', 'query', or 'move'. But got: ${fcn}`);
		return shim.error(`Unknown action, check the first argument, must be one of 'delete', 'query', or 'move'. But got: ${fcn}`);
	}

	async move(stub, args) {

		let A, B;
		let Aval, Bval;
		let X;

		if (args.length != 3) {
			return shim.error('Incorrect number of arguments. Expecting 3, function followed by 2 names and 1 value');
		}

		A = args[0];
		B = args[1];

		logger.info('Invoke move A: ' + A);
		logger.info('Invoke move B: ' + B);

		try {
			let Avalbytes = await stub.getState(A);
			if (!Avalbytes) {
				return shim.error('Entity A not found');
			}
			Aval = Avalbytes.toString();
			Aval = parseInt(Aval);
		} catch (e) {
			return shim.error('Failed to get state A');
		}

		try {
			let Bvalbytes = await stub.getState(B);
			if (!Bvalbytes) {
				return shim.error('Entity B not found');
			}
			Bval = Bvalbytes.toString();
			Bval = parseInt(Bval);
		} catch (e) {
			return shim.error('Failed to get state B');
		}
		// Perform the execution
		logger.info('Invoke move amount: ' + args[2]);
		X = parseInt(args[2]);
		logger.info('Invoke move amount as integert: ' + X);
		if (isNaN(X)) {
			return shim.error('Invalid transaction amount, expecting a integer value');
		}
		X = X * 2;
		Aval = Aval - X;
		Bval = Bval + X;
		logger.info(`Aval = ${Aval}, Bval = ${Bval}`);
		// Write the state back to the ledger
		try {
			await stub.putState(A, Buffer.from(Aval.toString()));
			await stub.putState(B, Buffer.from(Bval.toString()));
			let tmap = stub.getTransient();
			logger.info('Invoke move transient: ' + tmap);
			//JavaSDK expect to see events and results in transient maps just to test the feature and no other reason.
			if(tmap != null){
			 let event = tmap.get("event");
			 if(null != event){
			    stub.setEvent('event', event);
			 }

			 let rb = tmap.get("result");
			 logger.info('Invoke move transient requested result: ' + rb);
			 if( null != rb){
			  return shim.success(rb);}
			}
			return shim.success(Buffer.from('move succeed'));
		} catch (e) {
			return shim.error(e);
		}

	}

	async delete(stub, args) {
		if (args.length != 1) {
			return shim.error('Incorrect number of arguments. Expecting 1');
		}

		let A = args[0];

		try {
			await stub.deleteState(A);
		} catch (e) {
			return shim.error('Failed to delete state');
		}

		return shim.success();
	}

	async query(stub, args) {
		if (args.length != 1) {
			return shim.error('Incorrect number of arguments. Expecting name of the person to query');
		}

		let A = args[0];
		let Aval;
		// Get the state from the ledger
		try {
			let Avalbytes = await stub.getState(A);
			if (!Avalbytes) {
				return shim.error('Entity A not found');
			}
			Aval = Avalbytes.toString();
		} catch (e) {
			return shim.error('Failed to get state A');
		}

		let jsonResp = {
			Name: A,
			Amount: Aval
		};
		logger.info('Query Response:%s\n', JSON.stringify(jsonResp));

		return shim.success(Buffer.from(Aval.toString()));
	}
};

shim.start(new Chaincode());