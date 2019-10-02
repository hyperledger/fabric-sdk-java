/*
 *
 *  Copyright 2017, 2018 IBM Corp. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.hyperledger.fabric.sdk.idemix;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

import com.google.protobuf.ByteString;
import org.apache.milagro.amcl.FP256BN.BIG;
import org.apache.milagro.amcl.FP256BN.ECP;
import org.apache.milagro.amcl.FP256BN.ECP2;
import org.apache.milagro.amcl.FP256BN.FP12;
import org.apache.milagro.amcl.FP256BN.FP2;
import org.apache.milagro.amcl.FP256BN.PAIR;
import org.apache.milagro.amcl.FP256BN.ROM;
import org.apache.milagro.amcl.HASH256;
import org.apache.milagro.amcl.RAND;
import org.hyperledger.fabric.protos.idemix.Idemix;

/**
 * The class IdemixUtils consists of all needed utility functions for Idemix.
 * The class uses the apache milagro crypto library.
 */
public final class IdemixUtils {
    private static final BIG gx = new BIG(ROM.CURVE_Gx);
    private static final BIG gy = new BIG(ROM.CURVE_Gy);
    static final ECP genG1 = new ECP(gx, gy);
    private static final BIG pxa = new BIG(ROM.CURVE_Pxa);
    private static final BIG pxb = new BIG(ROM.CURVE_Pxb);
    private static final FP2 px = new FP2(pxa, pxb);
    private static final BIG pya = new BIG(ROM.CURVE_Pya);
    private static final BIG pyb = new BIG(ROM.CURVE_Pyb);
    private static final FP2 py = new FP2(pya, pyb);
    static final ECP2 genG2 = new ECP2(px, py);
    static final FP12 genGT = PAIR.fexp(PAIR.ate(genG2, genG1));
    static final BIG GROUP_ORDER = new BIG(ROM.CURVE_Order);
    static final int FIELD_BYTES = BIG.MODBYTES;

    private IdemixUtils() {
        // private constructor as there shouldn't be instances of this utility class
    }

    /**
     * Returns a random number generator, amcl.RAND,
     * initialized with a fresh seed.
     *
     * @return a random number generator
     */
     public static RAND getRand() {
        // construct a secure seed
        int seedLength = IdemixUtils.FIELD_BYTES;
        SecureRandom random = new SecureRandom();
        byte[] seed = random.generateSeed(seedLength);

        // create a new amcl.RAND and initialize it with the generated seed
        RAND rng = new RAND();
        rng.clean();
        rng.seed(seedLength, seed);

        return rng;
    }

    /**
     * @return a random BIG in 0, ..., GROUP_ORDER-1
     */
     public static BIG randModOrder(RAND rng) {
        BIG q = new BIG(ROM.CURVE_Order);

        // Takes random element in this Zq.
        return BIG.randomnum(q, rng);
    }

    /**
     * hashModOrder hashes bytes to an amcl.BIG
     * in 0, ..., GROUP_ORDER
     *
     * @param data the data to be hashed
     * @return a BIG in 0, ..., GROUP_ORDER-1 that is the hash of the data
     */
     public static BIG hashModOrder(byte[] data) {
        HASH256 hash = new HASH256();
        for (byte b : data) {
            hash.process(b);
        }

        byte[] hasheddata = hash.hash();

        BIG ret = BIG.fromBytes(hasheddata);
        ret.mod(IdemixUtils.GROUP_ORDER);

        return ret;
    }

    /**
     * bigToBytes turns a BIG into a byte array
     *
     * @param big the BIG to turn into bytes
     * @return a byte array representation of the BIG
     */
     public static byte[] bigToBytes(BIG big) {
        byte[] ret = new byte[IdemixUtils.FIELD_BYTES];
        big.toBytes(ret);
        return ret;
    }

    /**
     * ecpToBytes turns an ECP into a byte array
     *
     * @param e the ECP to turn into bytes
     * @return a byte array representation of the ECP
     */
     static byte[] ecpToBytes(ECP e) {
        byte[] ret = new byte[2 * FIELD_BYTES + 1];
        e.toBytes(ret, false);
        return ret;
    }

    /**
     * ecpToBytes turns an ECP2 into a byte array
     *
     * @param e the ECP2 to turn into bytes
     * @return a byte array representation of the ECP2
     */
     static byte[] ecpToBytes(ECP2 e) {
        byte[] ret = new byte[4 * FIELD_BYTES];
        e.toBytes(ret);
        return ret;
    }

    /**
     * append appends a byte array to an existing byte array
     *
     * @param data     the data to which we want to append
     * @param toAppend the data to be appended
     * @return a new byte[] of data + toAppend
     */
    static byte[] append(byte[] data, byte[] toAppend) {

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try {
            stream.write(data);
            stream.write(toAppend);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return stream.toByteArray();
    }

    /**
     * append appends a boolean array to an existing byte array
     * @param data     the data to which we want to append
     * @param toAppend the data to be appended
     * @return a new byte[] of data + toAppend
     */
    static byte[] append(byte[] data, boolean[] toAppend) {
        byte[] toAppendBytes = new byte[toAppend.length];
        for (int i = 0; i < toAppend.length; i++) {
            toAppendBytes[i] = toAppend[i] ? (byte) 1 : (byte) 0;
        }
        return append(data, toAppendBytes);
    }

    /**
     * Returns an amcl.BN256.ECP on input of an ECP protobuf object.
     *
     * @param w a protobuf object representing an ECP
     * @return a ECP created from the protobuf object
     */
     static ECP transformFromProto(Idemix.ECP w) {
        byte[] valuex = w.getX().toByteArray();
        byte[] valuey = w.getY().toByteArray();
        return new ECP(BIG.fromBytes(valuex), BIG.fromBytes(valuey));
    }

    /**
     * Returns an amcl.BN256.ECP2 on input of an ECP2 protobuf object.
     *
     * @param w a protobuf object representing an ECP2
     * @return a ECP2 created from the protobuf object
     */
     static ECP2 transformFromProto(Idemix.ECP2 w) {
        byte[] valuexa = w.getXa().toByteArray();
        byte[] valuexb = w.getXb().toByteArray();
        byte[] valueya = w.getYa().toByteArray();
        byte[] valueyb = w.getYb().toByteArray();
        FP2 valuex = new FP2(BIG.fromBytes(valuexa), BIG.fromBytes(valuexb));
        FP2 valuey = new FP2(BIG.fromBytes(valueya), BIG.fromBytes(valueyb));
        return new ECP2(valuex, valuey);
    }

    /**
     * Converts an amcl.BN256.ECP2 into an ECP2 protobuf object.
     *
     * @param w an ECP2 to be transformed into a protobuf object
     * @return a protobuf representation of the ECP2
     */
     static Idemix.ECP2 transformToProto(ECP2 w) {

        byte[] valueXA = new byte[IdemixUtils.FIELD_BYTES];
        byte[] valueXB = new byte[IdemixUtils.FIELD_BYTES];
        byte[] valueYA = new byte[IdemixUtils.FIELD_BYTES];
        byte[] valueYB = new byte[IdemixUtils.FIELD_BYTES];

        w.getX().getA().toBytes(valueXA);
        w.getX().getB().toBytes(valueXB);
        w.getY().getA().toBytes(valueYA);
        w.getY().getB().toBytes(valueYB);

        return Idemix.ECP2.newBuilder()
                .setXa(ByteString.copyFrom(valueXA))
                .setXb(ByteString.copyFrom(valueXB))
                .setYa(ByteString.copyFrom(valueYA))
                .setYb(ByteString.copyFrom(valueYB))
                .build();
    }

    /**
     * Converts an amcl.BN256.ECP into an ECP protobuf object.
     *
     * @param w an ECP to be transformed into a protobuf object
     * @return a protobuf representation of the ECP
     */
     static Idemix.ECP transformToProto(ECP w) {
        byte[] valueX = new byte[IdemixUtils.FIELD_BYTES];
        byte[] valueY = new byte[IdemixUtils.FIELD_BYTES];

        w.getX().toBytes(valueX);
        w.getY().toBytes(valueY);

        return Idemix.ECP.newBuilder().setX(ByteString.copyFrom(valueX)).setY(ByteString.copyFrom(valueY)).build();
    }

    /**
     * Takes input BIGs a, b, m and returns a+b modulo m
     *
     * @param a the first BIG to add
     * @param b the second BIG to add
     * @param m the modulus
     * @return Returns a+b (mod m)
     */
    static BIG modAdd(BIG a, BIG b, BIG m) {
        BIG c = a.plus(b);
        c.mod(m);
        return c;
    }

    /**
     * Modsub takes input BIGs a, b, m and returns a-b modulo m
     *
     * @param a the minuend of the modular subtraction
     * @param b the subtrahend of the modular subtraction
     * @param m the modulus
     * @return returns a-b (mod m)
     */
    static BIG modSub(BIG a, BIG b, BIG m) {
        return modAdd(a, BIG.modneg(b, m), m);
    }
}
