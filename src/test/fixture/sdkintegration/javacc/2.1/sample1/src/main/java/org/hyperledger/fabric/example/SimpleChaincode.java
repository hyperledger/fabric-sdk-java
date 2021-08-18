package org.hyperledger.fabric.example;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.shim.ChaincodeBase;
import org.hyperledger.fabric.shim.ChaincodeStub;
import org.hyperledger.fabric.shim.ResponseUtils;

public class SimpleChaincode extends ChaincodeBase {
    private static Log _logger = LogFactory.getLog(SimpleChaincode.class);

    @Override
    public Response init(ChaincodeStub stub) {
        try {
            _logger.info("Init java simple chaincode");
            String func = stub.getFunction();

            if (!func.equals("init")) {
                return ResponseUtils.newErrorResponse("function other than init is not supported");
            }
            List<String> args = stub.getParameters();
            if (args.size() != 4) {
                return ResponseUtils.newErrorResponse("Incorrect number of arguments. Expecting 4");
            }
            // Initialize the chaincode
            String account1Key = args.get(0);
            int account1Value = Integer.parseInt(args.get(1));
            String account2Key = args.get(2);
            int account2Value = Integer.parseInt(args.get(3));

            _logger.info(String.format("account %s, value = %s; account %s, value %s", account1Key, account1Value, account2Key, account2Value));
            stub.putStringState(account1Key, args.get(1));
            stub.putStringState(account2Key, args.get(3));

            return ResponseUtils.newSuccessResponse();
        } catch (Throwable e) {
            return ResponseUtils.newErrorResponse(e);
        }
    }

    @Override
    public Response invoke(ChaincodeStub stub) {
        try {
            _logger.info("Invoke java simple chaincode");
            String func = stub.getFunction();
            List<String> params = stub.getParameters();
            if (func.equals("move")) {
                return move(stub, params);
            }
            if (func.equals("delete")) {
                return delete(stub, params);
            }
            if (func.equals("query")) {
                return query(stub, params);
            }
            return ResponseUtils.newErrorResponse("Invalid invoke function name. Expecting one of: [\"move\", \"delete\", \"query\"]");
        } catch (Throwable e) {
            return ResponseUtils.newErrorResponse(e);
        }
    }

    private Response move(ChaincodeStub stub, List<String> args) {
        if (args.size() != 3) {
            return ResponseUtils.newErrorResponse("Incorrect number of arguments. Expecting 3");
        }
        String accountFromKey = args.get(0);
        String accountToKey = args.get(1);

        String accountFromValueStr = stub.getStringState(accountFromKey);
        if (accountFromValueStr == null) {
            return ResponseUtils.newErrorResponse(String.format("Entity %s not found", accountFromKey));
        }
        int accountFromValue = Integer.parseInt(accountFromValueStr);

        String accountToValueStr = stub.getStringState(accountToKey);
        if (accountToValueStr == null) {
            return ResponseUtils.newErrorResponse(String.format("Entity %s not found", accountToKey));
        }
        int accountToValue = Integer.parseInt(accountToValueStr);

        int amount = Integer.parseInt(args.get(2));

        if (amount > accountFromValue) {
            return ResponseUtils.newErrorResponse(String.format("not enough money in account %s", accountFromKey));
        }

        accountFromValue -= amount;
        accountToValue += amount;

        _logger.info(String.format("new value of A: %s", accountFromValue));
        _logger.info(String.format("new value of B: %s", accountToValue));

        stub.putStringState(accountFromKey, Integer.toString(accountFromValue));
        stub.putStringState(accountToKey, Integer.toString(accountToValue));

        _logger.info("Transfer complete");

        Map<String, byte[]> transientMap = stub.getTransient();
        if (null != transientMap) {
            if (transientMap.containsKey("event") && transientMap.get("event") != null) {
                stub.setEvent("event", transientMap.get("event"));
            }
            if (transientMap.containsKey("result") && transientMap.get("result") != null) {
                return ResponseUtils.newSuccessResponse(transientMap.get("result"));
            }
        }
        return ResponseUtils.newSuccessResponse();
    }

    // Deletes an entity from state
    private Response delete(ChaincodeStub stub, List<String> args) {
        if (args.size() != 1) {
            return ResponseUtils.newErrorResponse("Incorrect number of arguments. Expecting 1");
        }
        String key = args.get(0);
        // Delete the key from the state in ledger
        stub.delState(key);
        return ResponseUtils.newSuccessResponse();
    }

    // query callback representing the query of a chaincode
    private Response query(ChaincodeStub stub, List<String> args) {
        if (args.size() != 1) {
            return ResponseUtils.newErrorResponse("Incorrect number of arguments. Expecting name of the person to query");
        }
        String key = args.get(0);
        //byte[] stateBytes
        String val = stub.getStringState(key);
        if (val == null) {
            return ResponseUtils.newErrorResponse(String.format("Error: state for %s is null", key));
        }
        _logger.info(String.format("Query Response:\nName: %s, Amount: %s\n", key, val));
        return ResponseUtils.newSuccessResponse(val, val.getBytes(StandardCharsets.UTF_8));
    }

    public static void main(String[] args) {
        new SimpleChaincode().start(args);
    }
}
