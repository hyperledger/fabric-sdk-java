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
 * Interface exported by the server.
 * </pre>
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 0.15.0)",
    comments = "Source: peer/server_admin.proto")
public class AdminGrpc {

  private AdminGrpc() {}

  public static final String SERVICE_NAME = "protos.Admin";

  // Static method descriptors that strictly reflect the proto.
  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1901")
  public static final io.grpc.MethodDescriptor<com.google.protobuf.Empty,
      org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus> METHOD_GET_STATUS =
      io.grpc.MethodDescriptor.create(
          io.grpc.MethodDescriptor.MethodType.UNARY,
          generateFullMethodName(
              "protos.Admin", "GetStatus"),
          io.grpc.protobuf.ProtoUtils.marshaller(com.google.protobuf.Empty.getDefaultInstance()),
          io.grpc.protobuf.ProtoUtils.marshaller(org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus.getDefaultInstance()));
  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1901")
  public static final io.grpc.MethodDescriptor<com.google.protobuf.Empty,
      org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus> METHOD_START_SERVER =
      io.grpc.MethodDescriptor.create(
          io.grpc.MethodDescriptor.MethodType.UNARY,
          generateFullMethodName(
              "protos.Admin", "StartServer"),
          io.grpc.protobuf.ProtoUtils.marshaller(com.google.protobuf.Empty.getDefaultInstance()),
          io.grpc.protobuf.ProtoUtils.marshaller(org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus.getDefaultInstance()));
  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1901")
  public static final io.grpc.MethodDescriptor<com.google.protobuf.Empty,
      org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus> METHOD_STOP_SERVER =
      io.grpc.MethodDescriptor.create(
          io.grpc.MethodDescriptor.MethodType.UNARY,
          generateFullMethodName(
              "protos.Admin", "StopServer"),
          io.grpc.protobuf.ProtoUtils.marshaller(com.google.protobuf.Empty.getDefaultInstance()),
          io.grpc.protobuf.ProtoUtils.marshaller(org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus.getDefaultInstance()));
  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1901")
  public static final io.grpc.MethodDescriptor<org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest,
      org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse> METHOD_GET_MODULE_LOG_LEVEL =
      io.grpc.MethodDescriptor.create(
          io.grpc.MethodDescriptor.MethodType.UNARY,
          generateFullMethodName(
              "protos.Admin", "GetModuleLogLevel"),
          io.grpc.protobuf.ProtoUtils.marshaller(org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest.getDefaultInstance()),
          io.grpc.protobuf.ProtoUtils.marshaller(org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse.getDefaultInstance()));
  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1901")
  public static final io.grpc.MethodDescriptor<org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest,
      org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse> METHOD_SET_MODULE_LOG_LEVEL =
      io.grpc.MethodDescriptor.create(
          io.grpc.MethodDescriptor.MethodType.UNARY,
          generateFullMethodName(
              "protos.Admin", "SetModuleLogLevel"),
          io.grpc.protobuf.ProtoUtils.marshaller(org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest.getDefaultInstance()),
          io.grpc.protobuf.ProtoUtils.marshaller(org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse.getDefaultInstance()));

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static AdminStub newStub(io.grpc.Channel channel) {
    return new AdminStub(channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static AdminBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    return new AdminBlockingStub(channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary and streaming output calls on the service
   */
  public static AdminFutureStub newFutureStub(
      io.grpc.Channel channel) {
    return new AdminFutureStub(channel);
  }

  /**
   * <pre>
   * Interface exported by the server.
   * </pre>
   */
  @java.lang.Deprecated public static interface Admin {

    /**
     * <pre>
     * Return the serve status.
     * </pre>
     */
    public void getStatus(com.google.protobuf.Empty request,
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus> responseObserver);

    /**
     */
    public void startServer(com.google.protobuf.Empty request,
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus> responseObserver);

    /**
     */
    public void stopServer(com.google.protobuf.Empty request,
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus> responseObserver);

    /**
     */
    public void getModuleLogLevel(org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest request,
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse> responseObserver);

    /**
     */
    public void setModuleLogLevel(org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest request,
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse> responseObserver);
  }

  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1469")
  public static abstract class AdminImplBase implements Admin, io.grpc.BindableService {

    @java.lang.Override
    public void getStatus(com.google.protobuf.Empty request,
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus> responseObserver) {
      asyncUnimplementedUnaryCall(METHOD_GET_STATUS, responseObserver);
    }

    @java.lang.Override
    public void startServer(com.google.protobuf.Empty request,
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus> responseObserver) {
      asyncUnimplementedUnaryCall(METHOD_START_SERVER, responseObserver);
    }

    @java.lang.Override
    public void stopServer(com.google.protobuf.Empty request,
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus> responseObserver) {
      asyncUnimplementedUnaryCall(METHOD_STOP_SERVER, responseObserver);
    }

    @java.lang.Override
    public void getModuleLogLevel(org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest request,
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse> responseObserver) {
      asyncUnimplementedUnaryCall(METHOD_GET_MODULE_LOG_LEVEL, responseObserver);
    }

    @java.lang.Override
    public void setModuleLogLevel(org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest request,
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse> responseObserver) {
      asyncUnimplementedUnaryCall(METHOD_SET_MODULE_LOG_LEVEL, responseObserver);
    }

    @java.lang.Override public io.grpc.ServerServiceDefinition bindService() {
      return AdminGrpc.bindService(this);
    }
  }

  /**
   * <pre>
   * Interface exported by the server.
   * </pre>
   */
  @java.lang.Deprecated public static interface AdminBlockingClient {

    /**
     * <pre>
     * Return the serve status.
     * </pre>
     */
    public org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus getStatus(com.google.protobuf.Empty request);

    /**
     */
    public org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus startServer(com.google.protobuf.Empty request);

    /**
     */
    public org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus stopServer(com.google.protobuf.Empty request);

    /**
     */
    public org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse getModuleLogLevel(org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest request);

    /**
     */
    public org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse setModuleLogLevel(org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest request);
  }

  /**
   * <pre>
   * Interface exported by the server.
   * </pre>
   */
  @java.lang.Deprecated public static interface AdminFutureClient {

    /**
     * <pre>
     * Return the serve status.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus> getStatus(
        com.google.protobuf.Empty request);

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus> startServer(
        com.google.protobuf.Empty request);

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus> stopServer(
        com.google.protobuf.Empty request);

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse> getModuleLogLevel(
        org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest request);

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse> setModuleLogLevel(
        org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest request);
  }

  public static class AdminStub extends io.grpc.stub.AbstractStub<AdminStub>
      implements Admin {
    private AdminStub(io.grpc.Channel channel) {
      super(channel);
    }

    private AdminStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected AdminStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new AdminStub(channel, callOptions);
    }

    @java.lang.Override
    public void getStatus(com.google.protobuf.Empty request,
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus> responseObserver) {
      asyncUnaryCall(
          getChannel().newCall(METHOD_GET_STATUS, getCallOptions()), request, responseObserver);
    }

    @java.lang.Override
    public void startServer(com.google.protobuf.Empty request,
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus> responseObserver) {
      asyncUnaryCall(
          getChannel().newCall(METHOD_START_SERVER, getCallOptions()), request, responseObserver);
    }

    @java.lang.Override
    public void stopServer(com.google.protobuf.Empty request,
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus> responseObserver) {
      asyncUnaryCall(
          getChannel().newCall(METHOD_STOP_SERVER, getCallOptions()), request, responseObserver);
    }

    @java.lang.Override
    public void getModuleLogLevel(org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest request,
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse> responseObserver) {
      asyncUnaryCall(
          getChannel().newCall(METHOD_GET_MODULE_LOG_LEVEL, getCallOptions()), request, responseObserver);
    }

    @java.lang.Override
    public void setModuleLogLevel(org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest request,
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse> responseObserver) {
      asyncUnaryCall(
          getChannel().newCall(METHOD_SET_MODULE_LOG_LEVEL, getCallOptions()), request, responseObserver);
    }
  }

  public static class AdminBlockingStub extends io.grpc.stub.AbstractStub<AdminBlockingStub>
      implements AdminBlockingClient {
    private AdminBlockingStub(io.grpc.Channel channel) {
      super(channel);
    }

    private AdminBlockingStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected AdminBlockingStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new AdminBlockingStub(channel, callOptions);
    }

    @java.lang.Override
    public org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus getStatus(com.google.protobuf.Empty request) {
      return blockingUnaryCall(
          getChannel(), METHOD_GET_STATUS, getCallOptions(), request);
    }

    @java.lang.Override
    public org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus startServer(com.google.protobuf.Empty request) {
      return blockingUnaryCall(
          getChannel(), METHOD_START_SERVER, getCallOptions(), request);
    }

    @java.lang.Override
    public org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus stopServer(com.google.protobuf.Empty request) {
      return blockingUnaryCall(
          getChannel(), METHOD_STOP_SERVER, getCallOptions(), request);
    }

    @java.lang.Override
    public org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse getModuleLogLevel(org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest request) {
      return blockingUnaryCall(
          getChannel(), METHOD_GET_MODULE_LOG_LEVEL, getCallOptions(), request);
    }

    @java.lang.Override
    public org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse setModuleLogLevel(org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest request) {
      return blockingUnaryCall(
          getChannel(), METHOD_SET_MODULE_LOG_LEVEL, getCallOptions(), request);
    }
  }

  public static class AdminFutureStub extends io.grpc.stub.AbstractStub<AdminFutureStub>
      implements AdminFutureClient {
    private AdminFutureStub(io.grpc.Channel channel) {
      super(channel);
    }

    private AdminFutureStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected AdminFutureStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new AdminFutureStub(channel, callOptions);
    }

    @java.lang.Override
    public com.google.common.util.concurrent.ListenableFuture<org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus> getStatus(
        com.google.protobuf.Empty request) {
      return futureUnaryCall(
          getChannel().newCall(METHOD_GET_STATUS, getCallOptions()), request);
    }

    @java.lang.Override
    public com.google.common.util.concurrent.ListenableFuture<org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus> startServer(
        com.google.protobuf.Empty request) {
      return futureUnaryCall(
          getChannel().newCall(METHOD_START_SERVER, getCallOptions()), request);
    }

    @java.lang.Override
    public com.google.common.util.concurrent.ListenableFuture<org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus> stopServer(
        com.google.protobuf.Empty request) {
      return futureUnaryCall(
          getChannel().newCall(METHOD_STOP_SERVER, getCallOptions()), request);
    }

    @java.lang.Override
    public com.google.common.util.concurrent.ListenableFuture<org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse> getModuleLogLevel(
        org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest request) {
      return futureUnaryCall(
          getChannel().newCall(METHOD_GET_MODULE_LOG_LEVEL, getCallOptions()), request);
    }

    @java.lang.Override
    public com.google.common.util.concurrent.ListenableFuture<org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse> setModuleLogLevel(
        org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest request) {
      return futureUnaryCall(
          getChannel().newCall(METHOD_SET_MODULE_LOG_LEVEL, getCallOptions()), request);
    }
  }

  @java.lang.Deprecated public static abstract class AbstractAdmin extends AdminImplBase {}

  private static final int METHODID_GET_STATUS = 0;
  private static final int METHODID_START_SERVER = 1;
  private static final int METHODID_STOP_SERVER = 2;
  private static final int METHODID_GET_MODULE_LOG_LEVEL = 3;
  private static final int METHODID_SET_MODULE_LOG_LEVEL = 4;

  private static class MethodHandlers<Req, Resp> implements
      io.grpc.stub.ServerCalls.UnaryMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ServerStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ClientStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.BidiStreamingMethod<Req, Resp> {
    private final Admin serviceImpl;
    private final int methodId;

    public MethodHandlers(Admin serviceImpl, int methodId) {
      this.serviceImpl = serviceImpl;
      this.methodId = methodId;
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public void invoke(Req request, io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        case METHODID_GET_STATUS:
          serviceImpl.getStatus((com.google.protobuf.Empty) request,
              (io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus>) responseObserver);
          break;
        case METHODID_START_SERVER:
          serviceImpl.startServer((com.google.protobuf.Empty) request,
              (io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus>) responseObserver);
          break;
        case METHODID_STOP_SERVER:
          serviceImpl.stopServer((com.google.protobuf.Empty) request,
              (io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus>) responseObserver);
          break;
        case METHODID_GET_MODULE_LOG_LEVEL:
          serviceImpl.getModuleLogLevel((org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest) request,
              (io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse>) responseObserver);
          break;
        case METHODID_SET_MODULE_LOG_LEVEL:
          serviceImpl.setModuleLogLevel((org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest) request,
              (io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse>) responseObserver);
          break;
        default:
          throw new AssertionError();
      }
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public io.grpc.stub.StreamObserver<Req> invoke(
        io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        default:
          throw new AssertionError();
      }
    }
  }

  public static io.grpc.ServiceDescriptor getServiceDescriptor() {
    return new io.grpc.ServiceDescriptor(SERVICE_NAME,
        METHOD_GET_STATUS,
        METHOD_START_SERVER,
        METHOD_STOP_SERVER,
        METHOD_GET_MODULE_LOG_LEVEL,
        METHOD_SET_MODULE_LOG_LEVEL);
  }

  @java.lang.Deprecated public static io.grpc.ServerServiceDefinition bindService(
      final Admin serviceImpl) {
    return io.grpc.ServerServiceDefinition.builder(getServiceDescriptor())
        .addMethod(
          METHOD_GET_STATUS,
          asyncUnaryCall(
            new MethodHandlers<
              com.google.protobuf.Empty,
              org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus>(
                serviceImpl, METHODID_GET_STATUS)))
        .addMethod(
          METHOD_START_SERVER,
          asyncUnaryCall(
            new MethodHandlers<
              com.google.protobuf.Empty,
              org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus>(
                serviceImpl, METHODID_START_SERVER)))
        .addMethod(
          METHOD_STOP_SERVER,
          asyncUnaryCall(
            new MethodHandlers<
              com.google.protobuf.Empty,
              org.hyperledger.fabric.protos.peer.ServerAdmin.ServerStatus>(
                serviceImpl, METHODID_STOP_SERVER)))
        .addMethod(
          METHOD_GET_MODULE_LOG_LEVEL,
          asyncUnaryCall(
            new MethodHandlers<
              org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest,
              org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse>(
                serviceImpl, METHODID_GET_MODULE_LOG_LEVEL)))
        .addMethod(
          METHOD_SET_MODULE_LOG_LEVEL,
          asyncUnaryCall(
            new MethodHandlers<
              org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelRequest,
              org.hyperledger.fabric.protos.peer.ServerAdmin.LogLevelResponse>(
                serviceImpl, METHODID_SET_MODULE_LOG_LEVEL)))
        .build();
  }
}
