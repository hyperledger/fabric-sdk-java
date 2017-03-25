package org.hyperledger.fabric.sdkintegration;

import org.hyperledger.fabric_ca.sdkintegration.HFCAClientEnrollIT;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)

@Suite.SuiteClasses({
        End2endIT.class,
        End2endAndBackAgainIT.class,
        HFCAClientEnrollIT.class
})
public class IntegrationSuite {

}
