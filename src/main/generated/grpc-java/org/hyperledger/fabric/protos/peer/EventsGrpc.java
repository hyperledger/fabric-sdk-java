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
 * Interface exported by the events server
 * </pre>
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 0.15.0)",
    comments = "Source: peer/events.proto")
public class EventsGrpc {

  private EventsGrpc() {}

  public static final String SERVICE_NAME = "protos.Events";

  // Static method descriptors that strictly reflect the proto.
  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1901")
  public static final io.grpc.MethodDescriptor<org.hyperledger.fabric.protos.peer.EventsOuterClass.Event,
      org.hyperledger.fabric.protos.peer.EventsOuterClass.Event> METHOD_CHAT =
      io.grpc.MethodDescriptor.create(
          io.grpc.MethodDescriptor.MethodType.BIDI_STREAMING,
          generateFullMethodName(
              "protos.Events", "Chat"),
          io.grpc.protobuf.ProtoUtils.marshaller(org.hyperledger.fabric.protos.peer.EventsOuterClass.Event.getDefaultInstance()),
          io.grpc.protobuf.ProtoUtils.marshaller(org.hyperledger.fabric.protos.peer.EventsOuterClass.Event.getDefaultInstance()));

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static EventsStub newStub(io.grpc.Channel channel) {
    return new EventsStub(channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static EventsBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    return new EventsBlockingStub(channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary and streaming output calls on the service
   */
  public static EventsFutureStub newFutureStub(
      io.grpc.Channel channel) {
    return new EventsFutureStub(channel);
  }

  /**
   * <pre>
   * Interface exported by the events server
   * </pre>
   */
  @java.lang.Deprecated public static interface Events {

    /**
     * <pre>
     * event chatting using Event
     * </pre>
     */
    public io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.EventsOuterClass.Event> chat(
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.EventsOuterClass.Event> responseObserver);
  }

  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1469")
  public static abstract class EventsImplBase implements Events, io.grpc.BindableService {

    @java.lang.Override
    public io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.EventsOuterClass.Event> chat(
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.EventsOuterClass.Event> responseObserver) {
      return asyncUnimplementedStreamingCall(METHOD_CHAT, responseObserver);
    }

    @java.lang.Override public io.grpc.ServerServiceDefinition bindService() {
      return EventsGrpc.bindService(this);
    }
  }

  /**
   * <pre>
   * Interface exported by the events server
   * </pre>
   */
  @java.lang.Deprecated public static interface EventsBlockingClient {
  }

  /**
   * <pre>
   * Interface exported by the events server
   * </pre>
   */
  @java.lang.Deprecated public static interface EventsFutureClient {
  }

  public static class EventsStub extends io.grpc.stub.AbstractStub<EventsStub>
      implements Events {
    private EventsStub(io.grpc.Channel channel) {
      super(channel);
    }

    private EventsStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected EventsStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new EventsStub(channel, callOptions);
    }

    @java.lang.Override
    public io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.EventsOuterClass.Event> chat(
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.EventsOuterClass.Event> responseObserver) {
      return asyncBidiStreamingCall(
          getChannel().newCall(METHOD_CHAT, getCallOptions()), responseObserver);
    }
  }

  public static class EventsBlockingStub extends io.grpc.stub.AbstractStub<EventsBlockingStub>
      implements EventsBlockingClient {
    private EventsBlockingStub(io.grpc.Channel channel) {
      super(channel);
    }

    private EventsBlockingStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected EventsBlockingStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new EventsBlockingStub(channel, callOptions);
    }
  }

  public static class EventsFutureStub extends io.grpc.stub.AbstractStub<EventsFutureStub>
      implements EventsFutureClient {
    private EventsFutureStub(io.grpc.Channel channel) {
      super(channel);
    }

    private EventsFutureStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected EventsFutureStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new EventsFutureStub(channel, callOptions);
    }
  }

  @java.lang.Deprecated public static abstract class AbstractEvents extends EventsImplBase {}

  private static final int METHODID_CHAT = 0;

  private static class MethodHandlers<Req, Resp> implements
      io.grpc.stub.ServerCalls.UnaryMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ServerStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ClientStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.BidiStreamingMethod<Req, Resp> {
    private final Events serviceImpl;
    private final int methodId;

    public MethodHandlers(Events serviceImpl, int methodId) {
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
        case METHODID_CHAT:
          return (io.grpc.stub.StreamObserver<Req>) serviceImpl.chat(
              (io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.EventsOuterClass.Event>) responseObserver);
        default:
          throw new AssertionError();
      }
    }
  }

  public static io.grpc.ServiceDescriptor getServiceDescriptor() {
    return new io.grpc.ServiceDescriptor(SERVICE_NAME,
        METHOD_CHAT);
  }

  @java.lang.Deprecated public static io.grpc.ServerServiceDefinition bindService(
      final Events serviceImpl) {
    return io.grpc.ServerServiceDefinition.builder(getServiceDescriptor())
        .addMethod(
          METHOD_CHAT,
          asyncBidiStreamingCall(
            new MethodHandlers<
              org.hyperledger.fabric.protos.peer.EventsOuterClass.Event,
              org.hyperledger.fabric.protos.peer.EventsOuterClass.Event>(
                serviceImpl, METHODID_CHAT)))
        .build();
  }
}
