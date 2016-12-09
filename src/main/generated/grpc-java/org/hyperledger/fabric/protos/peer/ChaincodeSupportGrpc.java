package org.hyperledger.fabric.protos.peer;

import static io.grpc.stub.ClientCalls.asyncUnaryCall;
import static io.grpc.stub.ClientCalls.asyncServerStreamingCall;
import static io.grpc.stub.ClientCalls.asyncClientStreamingCall;
import static io.grpc.stub.ClientCalls.asyncBidiStreamingCall;
import static io.grpc.stub.ClientCalls.blockingUnaryCall;
import static io.grpc.stub.ClientCalls.blockingServerStreamingCall;
import static io.grpc.stub.ClientCalls.futureUnaryCall;
import static io.grpc.MethodDescriptor.generateFullMethodName;
import static io.grpc.stub.ServerCalls.asyncUnaryCall;
import static io.grpc.stub.ServerCalls.asyncServerStreamingCall;
import static io.grpc.stub.ServerCalls.asyncClientStreamingCall;
import static io.grpc.stub.ServerCalls.asyncBidiStreamingCall;
import static io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall;
import static io.grpc.stub.ServerCalls.asyncUnimplementedStreamingCall;

/**
 * <pre>
 * Interface that provides support to chaincode execution. ChaincodeContext
 * provides the context necessary for the server to respond appropriately.
 * </pre>
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 0.15.0)",
    comments = "Source: peer/chaincode.proto")
public class ChaincodeSupportGrpc {

  private ChaincodeSupportGrpc() {}

  public static final String SERVICE_NAME = "protos.ChaincodeSupport";

  // Static method descriptors that strictly reflect the proto.
  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1901")
  public static final io.grpc.MethodDescriptor<org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeMessage,
      org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeMessage> METHOD_REGISTER =
      io.grpc.MethodDescriptor.create(
          io.grpc.MethodDescriptor.MethodType.BIDI_STREAMING,
          generateFullMethodName(
              "protos.ChaincodeSupport", "Register"),
          io.grpc.protobuf.ProtoUtils.marshaller(org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeMessage.getDefaultInstance()),
          io.grpc.protobuf.ProtoUtils.marshaller(org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeMessage.getDefaultInstance()));

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static ChaincodeSupportStub newStub(io.grpc.Channel channel) {
    return new ChaincodeSupportStub(channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static ChaincodeSupportBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    return new ChaincodeSupportBlockingStub(channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary and streaming output calls on the service
   */
  public static ChaincodeSupportFutureStub newFutureStub(
      io.grpc.Channel channel) {
    return new ChaincodeSupportFutureStub(channel);
  }

  /**
   * <pre>
   * Interface that provides support to chaincode execution. ChaincodeContext
   * provides the context necessary for the server to respond appropriately.
   * </pre>
   */
  @java.lang.Deprecated public static interface ChaincodeSupport {

    /**
     */
    public io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeMessage> register(
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeMessage> responseObserver);
  }

  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1469")
  public static abstract class ChaincodeSupportImplBase implements ChaincodeSupport, io.grpc.BindableService {

    @java.lang.Override
    public io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeMessage> register(
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeMessage> responseObserver) {
      return asyncUnimplementedStreamingCall(METHOD_REGISTER, responseObserver);
    }

    @java.lang.Override public io.grpc.ServerServiceDefinition bindService() {
      return ChaincodeSupportGrpc.bindService(this);
    }
  }

  /**
   * <pre>
   * Interface that provides support to chaincode execution. ChaincodeContext
   * provides the context necessary for the server to respond appropriately.
   * </pre>
   */
  @java.lang.Deprecated public static interface ChaincodeSupportBlockingClient {
  }

  /**
   * <pre>
   * Interface that provides support to chaincode execution. ChaincodeContext
   * provides the context necessary for the server to respond appropriately.
   * </pre>
   */
  @java.lang.Deprecated public static interface ChaincodeSupportFutureClient {
  }

  public static class ChaincodeSupportStub extends io.grpc.stub.AbstractStub<ChaincodeSupportStub>
      implements ChaincodeSupport {
    private ChaincodeSupportStub(io.grpc.Channel channel) {
      super(channel);
    }

    private ChaincodeSupportStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected ChaincodeSupportStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new ChaincodeSupportStub(channel, callOptions);
    }

    @java.lang.Override
    public io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeMessage> register(
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeMessage> responseObserver) {
      return asyncBidiStreamingCall(
          getChannel().newCall(METHOD_REGISTER, getCallOptions()), responseObserver);
    }
  }

  public static class ChaincodeSupportBlockingStub extends io.grpc.stub.AbstractStub<ChaincodeSupportBlockingStub>
      implements ChaincodeSupportBlockingClient {
    private ChaincodeSupportBlockingStub(io.grpc.Channel channel) {
      super(channel);
    }

    private ChaincodeSupportBlockingStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected ChaincodeSupportBlockingStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new ChaincodeSupportBlockingStub(channel, callOptions);
    }
  }

  public static class ChaincodeSupportFutureStub extends io.grpc.stub.AbstractStub<ChaincodeSupportFutureStub>
      implements ChaincodeSupportFutureClient {
    private ChaincodeSupportFutureStub(io.grpc.Channel channel) {
      super(channel);
    }

    private ChaincodeSupportFutureStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected ChaincodeSupportFutureStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new ChaincodeSupportFutureStub(channel, callOptions);
    }
  }

  @java.lang.Deprecated public static abstract class AbstractChaincodeSupport extends ChaincodeSupportImplBase {}

  private static final int METHODID_REGISTER = 0;

  private static class MethodHandlers<Req, Resp> implements
      io.grpc.stub.ServerCalls.UnaryMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ServerStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ClientStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.BidiStreamingMethod<Req, Resp> {
    private final ChaincodeSupport serviceImpl;
    private final int methodId;

    public MethodHandlers(ChaincodeSupport serviceImpl, int methodId) {
      this.serviceImpl = serviceImpl;
      this.methodId = methodId;
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public void invoke(Req request, io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        default:
          throw new AssertionError();
      }
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public io.grpc.stub.StreamObserver<Req> invoke(
        io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        case METHODID_REGISTER:
          return (io.grpc.stub.StreamObserver<Req>) serviceImpl.register(
              (io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeMessage>) responseObserver);
        default:
          throw new AssertionError();
      }
    }
  }

  public static io.grpc.ServiceDescriptor getServiceDescriptor() {
    return new io.grpc.ServiceDescriptor(SERVICE_NAME,
        METHOD_REGISTER);
  }

  @java.lang.Deprecated public static io.grpc.ServerServiceDefinition bindService(
      final ChaincodeSupport serviceImpl) {
    return io.grpc.ServerServiceDefinition.builder(getServiceDescriptor())
        .addMethod(
          METHOD_REGISTER,
          asyncBidiStreamingCall(
            new MethodHandlers<
              org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeMessage,
              org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeMessage>(
                serviceImpl, METHODID_REGISTER)))
        .build();
  }
}
