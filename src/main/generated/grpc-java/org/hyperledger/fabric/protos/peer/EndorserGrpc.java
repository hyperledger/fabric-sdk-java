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
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 0.15.0)",
    comments = "Source: peer/fabric_service.proto")
public class EndorserGrpc {

  private EndorserGrpc() {}

  public static final String SERVICE_NAME = "protos.Endorser";

  // Static method descriptors that strictly reflect the proto.
  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1901")
  public static final io.grpc.MethodDescriptor<org.hyperledger.fabric.protos.peer.FabricProposal.SignedProposal,
      org.hyperledger.fabric.protos.peer.FabricProposalResponse.ProposalResponse> METHOD_PROCESS_PROPOSAL =
      io.grpc.MethodDescriptor.create(
          io.grpc.MethodDescriptor.MethodType.UNARY,
          generateFullMethodName(
              "protos.Endorser", "ProcessProposal"),
          io.grpc.protobuf.ProtoUtils.marshaller(org.hyperledger.fabric.protos.peer.FabricProposal.SignedProposal.getDefaultInstance()),
          io.grpc.protobuf.ProtoUtils.marshaller(org.hyperledger.fabric.protos.peer.FabricProposalResponse.ProposalResponse.getDefaultInstance()));

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static EndorserStub newStub(io.grpc.Channel channel) {
    return new EndorserStub(channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static EndorserBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    return new EndorserBlockingStub(channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary and streaming output calls on the service
   */
  public static EndorserFutureStub newFutureStub(
      io.grpc.Channel channel) {
    return new EndorserFutureStub(channel);
  }

  /**
   */
  @java.lang.Deprecated public static interface Endorser {

    /**
     */
    public void processProposal(org.hyperledger.fabric.protos.peer.FabricProposal.SignedProposal request,
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.FabricProposalResponse.ProposalResponse> responseObserver);
  }

  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1469")
  public static abstract class EndorserImplBase implements Endorser, io.grpc.BindableService {

    @java.lang.Override
    public void processProposal(org.hyperledger.fabric.protos.peer.FabricProposal.SignedProposal request,
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.FabricProposalResponse.ProposalResponse> responseObserver) {
      asyncUnimplementedUnaryCall(METHOD_PROCESS_PROPOSAL, responseObserver);
    }

    @java.lang.Override public io.grpc.ServerServiceDefinition bindService() {
      return EndorserGrpc.bindService(this);
    }
  }

  /**
   */
  @java.lang.Deprecated public static interface EndorserBlockingClient {

    /**
     */
    public org.hyperledger.fabric.protos.peer.FabricProposalResponse.ProposalResponse processProposal(org.hyperledger.fabric.protos.peer.FabricProposal.SignedProposal request);
  }

  /**
   */
  @java.lang.Deprecated public static interface EndorserFutureClient {

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<org.hyperledger.fabric.protos.peer.FabricProposalResponse.ProposalResponse> processProposal(
        org.hyperledger.fabric.protos.peer.FabricProposal.SignedProposal request);
  }

  public static class EndorserStub extends io.grpc.stub.AbstractStub<EndorserStub>
      implements Endorser {
    private EndorserStub(io.grpc.Channel channel) {
      super(channel);
    }

    private EndorserStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected EndorserStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new EndorserStub(channel, callOptions);
    }

    @java.lang.Override
    public void processProposal(org.hyperledger.fabric.protos.peer.FabricProposal.SignedProposal request,
        io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.FabricProposalResponse.ProposalResponse> responseObserver) {
      asyncUnaryCall(
          getChannel().newCall(METHOD_PROCESS_PROPOSAL, getCallOptions()), request, responseObserver);
    }
  }

  public static class EndorserBlockingStub extends io.grpc.stub.AbstractStub<EndorserBlockingStub>
      implements EndorserBlockingClient {
    private EndorserBlockingStub(io.grpc.Channel channel) {
      super(channel);
    }

    private EndorserBlockingStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected EndorserBlockingStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new EndorserBlockingStub(channel, callOptions);
    }

    @java.lang.Override
    public org.hyperledger.fabric.protos.peer.FabricProposalResponse.ProposalResponse processProposal(org.hyperledger.fabric.protos.peer.FabricProposal.SignedProposal request) {
      return blockingUnaryCall(
          getChannel(), METHOD_PROCESS_PROPOSAL, getCallOptions(), request);
    }
  }

  public static class EndorserFutureStub extends io.grpc.stub.AbstractStub<EndorserFutureStub>
      implements EndorserFutureClient {
    private EndorserFutureStub(io.grpc.Channel channel) {
      super(channel);
    }

    private EndorserFutureStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected EndorserFutureStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new EndorserFutureStub(channel, callOptions);
    }

    @java.lang.Override
    public com.google.common.util.concurrent.ListenableFuture<org.hyperledger.fabric.protos.peer.FabricProposalResponse.ProposalResponse> processProposal(
        org.hyperledger.fabric.protos.peer.FabricProposal.SignedProposal request) {
      return futureUnaryCall(
          getChannel().newCall(METHOD_PROCESS_PROPOSAL, getCallOptions()), request);
    }
  }

  @java.lang.Deprecated public static abstract class AbstractEndorser extends EndorserImplBase {}

  private static final int METHODID_PROCESS_PROPOSAL = 0;

  private static class MethodHandlers<Req, Resp> implements
      io.grpc.stub.ServerCalls.UnaryMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ServerStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ClientStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.BidiStreamingMethod<Req, Resp> {
    private final Endorser serviceImpl;
    private final int methodId;

    public MethodHandlers(Endorser serviceImpl, int methodId) {
      this.serviceImpl = serviceImpl;
      this.methodId = methodId;
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public void invoke(Req request, io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        case METHODID_PROCESS_PROPOSAL:
          serviceImpl.processProposal((org.hyperledger.fabric.protos.peer.FabricProposal.SignedProposal) request,
              (io.grpc.stub.StreamObserver<org.hyperledger.fabric.protos.peer.FabricProposalResponse.ProposalResponse>) responseObserver);
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
        METHOD_PROCESS_PROPOSAL);
  }

  @java.lang.Deprecated public static io.grpc.ServerServiceDefinition bindService(
      final Endorser serviceImpl) {
    return io.grpc.ServerServiceDefinition.builder(getServiceDescriptor())
        .addMethod(
          METHOD_PROCESS_PROPOSAL,
          asyncUnaryCall(
            new MethodHandlers<
              org.hyperledger.fabric.protos.peer.FabricProposal.SignedProposal,
              org.hyperledger.fabric.protos.peer.FabricProposalResponse.ProposalResponse>(
                serviceImpl, METHODID_PROCESS_PROPOSAL)))
        .build();
  }
}
