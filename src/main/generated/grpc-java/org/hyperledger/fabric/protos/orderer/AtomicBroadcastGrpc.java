package org.hyperledger.fabric.protos.orderer;

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
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 0.15.0)",
    comments = "Source: orderer/ab.proto")
public class AtomicBroadcastGrpc {

  private AtomicBroadcastGrpc() {}

  public static final String SERVICE_NAME = "orderer.AtomicBroadcast";

  // Static method descriptors that strictly reflect the proto.
  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1901")
  public static final io.grpc.MethodDescriptor<org.hyperledger.fabric.protos.common.Common.Envelope,
      org.hyperledger.fabric.protos.orderer.Ab.BroadcastResponse> METHOD_BROADCAST =
      io.grpc.MethodDescriptor.create(
          io.grpc.MethodDescriptor.MethodType.BIDI_STREAMING,
          generateFullMethodName(
              "orderer.AtomicBroadcast", "Broadcast"),
          io.grpc.protobuf.ProtoUtils.marshaller(org.hyperledger.fabric.protos.common.Common.Envelope.getDefaultInstance()),
          io.grpc.protobuf.ProtoUtils.marshaller(org.hyperledger.fabric.protos.orderer.Ab.BroadcastResponse.getDefaultInstance()));
  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1901")
  public static final io.grpc.MethodDescriptor<org.hyperledger.fabric.protos.orderer.Ab.DeliverUpdate,
      org.hyperledger.fabric.protos.orderer.Ab.DeliverResponse> METHOD_DELIVER =
      io.grpc.MethodDescriptor.create(
          io.grpc.MethodDescriptor.MethodType.BIDI_STREAMING,
          generateFullMethodName(
              "orderer.AtomicBroadcast", "Deliver"),
          io.grpc.protobuf.ProtoUtils.marshaller(org.hyperledger.fabric.protos.orderer.Ab.DeliverUpdate.getDefaultInstance()),
          io.grpc.protobuf.ProtoUtils.marshaller(org.hyperledger.fabric.protos.orderer.Ab.DeliverResponse.getDefaultInstance()));

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static AtomicBroadcastStub newStub(io.grpc.Channel channel) {
    return new AtomicBroadcastStub(channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static AtomicBroadcastBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    return new AtomicBroadcastBlockingStub(channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary and streaming output calls on the service
   */
  public static AtomicBroadcastFutureStub newFutureStub(
      io.grpc.Channel channel) {
    return new AtomicBroadcastFutureStub(channel);
  }

  /**
   */
  @java.lang.Deprecated public static interface AtomicBroadcast {

    /**
     * <pre>
     * broadcast receives a reply of Acknowledgement for each common.Envelope in order, indicating success or type of failure
     * </pre>
     */
    public io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.common.Common.Envelope> broadcast(
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.orderer.Ab.BroadcastResponse> responseObserver);

    /**
     * <pre>
     * deliver first requires an update containing a seek message, then a stream of block replies is received.
     * The receiver may choose to send an Acknowledgement for any block number it receives, however Acknowledgements must never be more than WindowSize apart
     * To avoid latency, clients will likely acknowledge before the WindowSize has been exhausted, preventing the server from stopping and waiting for an Acknowledgement
     * </pre>
     */
    public io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.orderer.Ab.DeliverUpdate> deliver(
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.orderer.Ab.DeliverResponse> responseObserver);
  }

  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1469")
  public static abstract class AtomicBroadcastImplBase implements AtomicBroadcast, io.grpc.BindableService {

    @java.lang.Override
    public io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.common.Common.Envelope> broadcast(
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.orderer.Ab.BroadcastResponse> responseObserver) {
      return asyncUnimplementedStreamingCall(METHOD_BROADCAST, responseObserver);
    }

    @java.lang.Override
    public io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.orderer.Ab.DeliverUpdate> deliver(
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.orderer.Ab.DeliverResponse> responseObserver) {
      return asyncUnimplementedStreamingCall(METHOD_DELIVER, responseObserver);
    }

    @java.lang.Override public io.grpc.ServerServiceDefinition bindService() {
      return AtomicBroadcastGrpc.bindService(this);
    }
  }

  /**
   */
  @java.lang.Deprecated public static interface AtomicBroadcastBlockingClient {
  }

  /**
   */
  @java.lang.Deprecated public static interface AtomicBroadcastFutureClient {
  }

  public static class AtomicBroadcastStub extends io.grpc.stub.AbstractStub<AtomicBroadcastStub>
      implements AtomicBroadcast {
    private AtomicBroadcastStub(io.grpc.Channel channel) {
      super(channel);
    }

    private AtomicBroadcastStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected AtomicBroadcastStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new AtomicBroadcastStub(channel, callOptions);
    }

    @java.lang.Override
    public io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.common.Common.Envelope> broadcast(
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.orderer.Ab.BroadcastResponse> responseObserver) {
      return asyncBidiStreamingCall(
          getChannel().newCall(METHOD_BROADCAST, getCallOptions()), responseObserver);
    }

    @java.lang.Override
    public io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.orderer.Ab.DeliverUpdate> deliver(
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.orderer.Ab.DeliverResponse> responseObserver) {
      return asyncBidiStreamingCall(
          getChannel().newCall(METHOD_DELIVER, getCallOptions()), responseObserver);
    }
  }

  public static class AtomicBroadcastBlockingStub extends io.grpc.stub.AbstractStub<AtomicBroadcastBlockingStub>
      implements AtomicBroadcastBlockingClient {
    private AtomicBroadcastBlockingStub(io.grpc.Channel channel) {
      super(channel);
    }

    private AtomicBroadcastBlockingStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected AtomicBroadcastBlockingStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new AtomicBroadcastBlockingStub(channel, callOptions);
    }
  }

  public static class AtomicBroadcastFutureStub extends io.grpc.stub.AbstractStub<AtomicBroadcastFutureStub>
      implements AtomicBroadcastFutureClient {
    private AtomicBroadcastFutureStub(io.grpc.Channel channel) {
      super(channel);
    }

    private AtomicBroadcastFutureStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected AtomicBroadcastFutureStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new AtomicBroadcastFutureStub(channel, callOptions);
    }
  }

  @java.lang.Deprecated public static abstract class AbstractAtomicBroadcast extends AtomicBroadcastImplBase {}

  private static final int METHODID_BROADCAST = 0;
  private static final int METHODID_DELIVER = 1;

  private static class MethodHandlers<Req, Resp> implements
      io.grpc.stub.ServerCalls.UnaryMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ServerStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ClientStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.BidiStreamingMethod<Req, Resp> {
    private final AtomicBroadcast serviceImpl;
    private final int methodId;

    public MethodHandlers(AtomicBroadcast serviceImpl, int methodId) {
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
        case METHODID_BROADCAST:
          return (io.grpc.stub.StreamObserver<Req>) serviceImpl.broadcast(
              (io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.orderer.Ab.BroadcastResponse>) responseObserver);
        case METHODID_DELIVER:
          return (io.grpc.stub.StreamObserver<Req>) serviceImpl.deliver(
              (io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.orderer.Ab.DeliverResponse>) responseObserver);
        default:
          throw new AssertionError();
      }
    }
  }

  public static io.grpc.ServiceDescriptor getServiceDescriptor() {
    return new io.grpc.ServiceDescriptor(SERVICE_NAME,
        METHOD_BROADCAST,
        METHOD_DELIVER);
  }

  @java.lang.Deprecated public static io.grpc.ServerServiceDefinition bindService(
      final AtomicBroadcast serviceImpl) {
    return io.grpc.ServerServiceDefinition.builder(getServiceDescriptor())
        .addMethod(
          METHOD_BROADCAST,
          asyncBidiStreamingCall(
            new MethodHandlers<
              org.hyperledger.fabric.protos.common.Common.Envelope,
              org.hyperledger.fabric.protos.orderer.Ab.BroadcastResponse>(
                serviceImpl, METHODID_BROADCAST)))
        .addMethod(
          METHOD_DELIVER,
          asyncBidiStreamingCall(
            new MethodHandlers<
              org.hyperledger.fabric.protos.orderer.Ab.DeliverUpdate,
              org.hyperledger.fabric.protos.orderer.Ab.DeliverResponse>(
                serviceImpl, METHODID_DELIVER)))
        .build();
  }
}
