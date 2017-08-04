/*
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk.security;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.helper.Config;

/**
 * SDK's Default implementation of CryptoSuiteFactory.
 */
public class HLSDKJCryptoSuiteFactory implements CryptoSuiteFactory {
    private static final Config config = Config.getConfig();
    private static final int SECURITY_LEVEL = config.getSecurityLevel();
    private static final String HASH_ALGORITHM = config.getHashAlgorithm();

    private HLSDKJCryptoSuiteFactory() {

    }

    private static final Map<Properties, CryptoSuite> cache = new ConcurrentHashMap<>();

    @Override
    public CryptoSuite getCryptoSuite(Properties properties) throws CryptoException, InvalidArgumentException {

        CryptoSuite ret = cache.get(properties);
        if (ret == null) {
            try {
                CryptoPrimitives cp = new CryptoPrimitives();
                cp.setProperties(properties);
                cp.init();
                ret = cp;
            } catch (Exception e) {
                throw new CryptoException(e.getMessage(), e);
            }

            cache.put(properties, ret);

        }

        return ret;

    }

    @Override
    public CryptoSuite getCryptoSuite() throws CryptoException, InvalidArgumentException {

        Properties properties = new Properties();
        properties.put(Config.SECURITY_LEVEL, SECURITY_LEVEL);
        properties.put(Config.HASH_ALGORITHM, HASH_ALGORITHM);

        return getCryptoSuite(properties);
    }

    private static final HLSDKJCryptoSuiteFactory INSTANCE = new HLSDKJCryptoSuiteFactory();

    static synchronized HLSDKJCryptoSuiteFactory instance() {

        return INSTANCE;
    }

    private static CryptoSuiteFactory theFACTORY = null; // one and only factory.

    static final synchronized CryptoSuiteFactory getDefault() throws ClassNotFoundException, IllegalAccessException, InstantiationException, NoSuchMethodException, InvocationTargetException {

        if (null == theFACTORY) {

            String cf = config.getDefaultCryptoSuiteFactory();
            if (null == cf || cf.isEmpty() || cf.equals(HLSDKJCryptoSuiteFactory.class.getName())) { // Use this class as the factory.

                theFACTORY = HLSDKJCryptoSuiteFactory.instance();

            } else {

                // Invoke static method instance on factory class specified by config properties.
                // In this case this class will no longer be used as the factory.

                Class<?> aClass = Class.forName(cf);

                Method method = aClass.getMethod("instance");
                Object theFACTORYObject = method.invoke(null);
                if (null == theFACTORYObject) {
                    throw new InstantiationException(String.format("Class specified by %s has instance method returning null.  Expected object implementing CryptoSuiteFactory interface.", cf));
                }

                if (!(theFACTORYObject instanceof CryptoSuiteFactory)) {

                    throw new InstantiationException(String.format("Class specified by %s has instance method returning a class %s which does not implement interface CryptoSuiteFactory ",
                            cf, theFACTORYObject.getClass().getName()));

                }

                theFACTORY = (CryptoSuiteFactory) theFACTORYObject;

            }
        }

        return theFACTORY;
    }

}