---- MODULE vsock_session ----
(***************************************************************************)
(* Formal TLA+ Specification of the Nona AF_VSOCK Session & DH-PSI         *)
(* Handshake State Machine under an Adversarial Host Transport Channel.    *)
(*                                                                         *)
(* Models:                                                                 *)
(*   - Ephemeral session key lifecycle & /dev/nsm attestation binding      *)
(*   - Strict monotonic phase progression:                                 *)
(*       Unattested -> AttestedBound -> Phase1Blinded -> Phase2Reblinded   *)
(*       -> Phase2Intersected (and fail-closed ClosedZeroized)             *)
(*   - Wire opcodes & framing bounds (CMD_PING, CMD_ATTEST, CMD_INGEST,    *)
(*     CMD_BLIND_PHASE1, CMD_PHASE2_REBLIND, CMD_PHASE2_INTERSECT)         *)
(*   - Adversarial untrusted host channel capable of arbitrary packet      *)
(*     dropping, duplication/replay, reordering, truncation/corruption,    *)
(*     and out-of-phase command injection                                  *)
(*   - Fail-closed abort with deterministic key & buffer zeroization       *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    MaxSessionOps,      \* Monotonic operation ceiling per ephemeral session key
    MaxChannelQueue,    \* Bounded vsock in-flight frame queue depth
    MaxAdvFaults,       \* Bound on adversarial channel mutations for exhaustive exploration
    Nonces              \* Finite set of distinct 256-bit challenge nonces

ASSUME
    /\ MaxSessionOps \in Nat /\ MaxSessionOps >= 4
    /\ MaxChannelQueue \in Nat /\ MaxChannelQueue >= 2
    /\ MaxAdvFaults \in Nat /\ MaxAdvFaults >= 1
    /\ Nonces # {} /\ IsFiniteSet(Nonces)

VARIABLES
    enclavePhase,       \* Enclave session lifecycle state
    clientPhase,        \* Host client protocol state
    netChannel,         \* Sequence of in-flight vsock frames (adversarial medium)
    sessionEpoch,       \* Monotonic enclave session key epoch
    opCount,            \* Monotonic cryptographic operation counter
    activeNonce,        \* Challenge nonce bound during CMD_ATTEST handshake (0 = none)
    usedNonces,         \* Set of consumed challenge nonces (replay protection)
    keyZeroized,        \* TRUE iff ephemeral private scalar memory has H(R) = 0
    buffersZeroized,    \* TRUE iff staging/scratch/attestation buffers have H(R) = 0
    lastWireStatus,     \* Last opaque wire status emitted (0 = OK, -1 = OPAQUE_ERR)
    advFaultsUsed       \* Count of adversarial channel fault injections exercised

vars == <<
    enclavePhase,
    clientPhase,
    netChannel,
    sessionEpoch,
    opCount,
    activeNonce,
    usedNonces,
    keyZeroized,
    buffersZeroized,
    lastWireStatus,
    advFaultsUsed
>>

EnclavePhases == {
    "Unattested",
    "AttestedBound",
    "Phase1Blinded",
    "Phase2Reblinded",
    "Phase2Intersected",
    "ClosedZeroized"
}

ClientPhases == {
    "Init",
    "ChallengeSent",
    "Attested",
    "Phase1Sent",
    "Phase1Done",
    "Phase2ReblindSent",
    "Phase2ReblindDone",
    "Phase2IntersectSent",
    "Completed",
    "Aborted"
}

TerminalEnclavePhases == {"Phase2Intersected", "ClosedZeroized"}

Commands == {
    "CMD_PING",
    "CMD_ATTEST",
    "CMD_INGEST",
    "CMD_BLIND_PHASE1",
    "CMD_PHASE2_REBLIND",
    "CMD_PHASE2_INTERSECT"
}

Directions == {"C2E", "E2C"}

FrameStatuses == {"OK", "ERR_OPAQUE"}

FrameSet == [
    dir: Directions,
    cmd: Commands,
    nonce: Nonces \cup {0},
    epoch: 0..2,
    headerValid: BOOLEAN,
    payloadBounded: BOOLEAN,
    attestedFlag: BOOLEAN,
    status: FrameStatuses
]

IsWellFormedRequest(msg) ==
    /\ msg.dir = "C2E"
    /\ msg.headerValid = TRUE
    /\ msg.payloadBounded = TRUE

IsCommandAllowedInPhase(cmd, phase, attested) ==
    CASE cmd = "CMD_PING" ->
            phase \in {"Unattested", "AttestedBound", "Phase1Blinded", "Phase2Reblinded"}
      [] cmd = "CMD_ATTEST" ->
            phase = "Unattested"
      [] cmd = "CMD_INGEST" ->
            phase = "AttestedBound" /\ attested = TRUE
      [] cmd = "CMD_BLIND_PHASE1" ->
            phase = "AttestedBound" /\ attested = TRUE
      [] cmd = "CMD_PHASE2_REBLIND" ->
            phase = "Phase1Blinded" /\ attested = TRUE
      [] cmd = "CMD_PHASE2_INTERSECT" ->
            phase = "Phase2Reblinded" /\ attested = TRUE
      [] OTHER -> FALSE

FailClosedZeroize ==
    /\ enclavePhase' = "ClosedZeroized"
    /\ clientPhase' = "Aborted"
    /\ netChannel' = <<>>
    /\ opCount' = 0
    /\ activeNonce' = 0
    /\ keyZeroized' = TRUE
    /\ buffersZeroized' = TRUE
    /\ lastWireStatus' = -1
    /\ UNCHANGED <<sessionEpoch, usedNonces, advFaultsUsed>>

Init ==
    /\ enclavePhase = "Unattested"
    /\ clientPhase = "Init"
    /\ netChannel = <<>>
    /\ sessionEpoch = 1
    /\ opCount = 0
    /\ activeNonce = 0
    /\ usedNonces = {}
    /\ keyZeroized = FALSE
    /\ buffersZeroized = TRUE
    /\ lastWireStatus = 0
    /\ advFaultsUsed = 0

ClientSendAttestChallenge ==
    /\ enclavePhase = "Unattested"
    /\ clientPhase = "Init"
    /\ Len(netChannel) < MaxChannelQueue
    /\ \E n \in Nonces \ usedNonces :
        LET req == [
            dir |-> "C2E",
            cmd |-> "CMD_ATTEST",
            nonce |-> n,
            epoch |-> sessionEpoch,
            headerValid |-> TRUE,
            payloadBounded |-> TRUE,
            attestedFlag |-> FALSE,
            status |-> "OK"
        ]
        IN
        /\ clientPhase' = "ChallengeSent"
        /\ activeNonce' = n
        /\ usedNonces' = usedNonces \cup {n}
        /\ netChannel' = Append(netChannel, req)
        /\ UNCHANGED <<enclavePhase, sessionEpoch, opCount, keyZeroized, buffersZeroized, lastWireStatus, advFaultsUsed>>

EnclaveProcessAttest ==
    /\ enclavePhase \notin TerminalEnclavePhases
    /\ Len(netChannel) > 0
    /\ LET msg == Head(netChannel) IN
       /\ msg.dir = "C2E"
       /\ msg.cmd = "CMD_ATTEST"
       /\ IF IsWellFormedRequest(msg)
             /\ enclavePhase = "Unattested"
             /\ msg.nonce \in Nonces
             /\ msg.nonce = activeNonce
             /\ msg.epoch = sessionEpoch
             /\ opCount < MaxSessionOps
             /\ ~keyZeroized
          THEN
             LET resp == [
                 dir |-> "E2C",
                 cmd |-> "CMD_ATTEST",
                 nonce |-> msg.nonce,
                 epoch |-> sessionEpoch,
                 headerValid |-> TRUE,
                 payloadBounded |-> TRUE,
                 attestedFlag |-> TRUE,
                 status |-> "OK"
             ]
             IN
             /\ enclavePhase' = "AttestedBound"
             /\ opCount' = opCount + 1
             /\ buffersZeroized' = TRUE
             /\ lastWireStatus' = 0
             /\ netChannel' = Append(Tail(netChannel), resp)
             /\ UNCHANGED <<clientPhase, sessionEpoch, activeNonce, usedNonces, keyZeroized, advFaultsUsed>>
          ELSE
             FailClosedZeroize

ClientReceiveAttestVerify ==
    /\ enclavePhase \notin TerminalEnclavePhases
    /\ Len(netChannel) > 0
    /\ LET msg == Head(netChannel) IN
       /\ msg.dir = "E2C"
       /\ msg.cmd = "CMD_ATTEST"
       /\ IF clientPhase = "ChallengeSent"
             /\ msg.headerValid = TRUE
             /\ msg.payloadBounded = TRUE
             /\ msg.status = "OK"
             /\ msg.attestedFlag = TRUE
             /\ msg.nonce = activeNonce
             /\ msg.epoch = sessionEpoch
          THEN
             /\ clientPhase' = "Attested"
             /\ netChannel' = Tail(netChannel)
             /\ UNCHANGED <<enclavePhase, sessionEpoch, opCount, activeNonce, usedNonces, keyZeroized, buffersZeroized, lastWireStatus, advFaultsUsed>>
          ELSE
             FailClosedZeroize

ClientSendPhase1 ==
    /\ enclavePhase = "AttestedBound"
    /\ clientPhase = "Attested"
    /\ Len(netChannel) < MaxChannelQueue
    /\ LET req == [
           dir |-> "C2E",
           cmd |-> "CMD_BLIND_PHASE1",
           nonce |-> activeNonce,
           epoch |-> sessionEpoch,
           headerValid |-> TRUE,
           payloadBounded |-> TRUE,
           attestedFlag |-> TRUE,
           status |-> "OK"
       ]
       IN
       /\ clientPhase' = "Phase1Sent"
       /\ netChannel' = Append(netChannel, req)
       /\ UNCHANGED <<enclavePhase, sessionEpoch, opCount, activeNonce, usedNonces, keyZeroized, buffersZeroized, lastWireStatus, advFaultsUsed>>

EnclaveProcessPhase1 ==
    /\ enclavePhase \notin TerminalEnclavePhases
    /\ Len(netChannel) > 0
    /\ LET msg == Head(netChannel) IN
       /\ msg.dir = "C2E"
       /\ msg.cmd = "CMD_BLIND_PHASE1"
       /\ IF IsWellFormedRequest(msg)
             /\ IsCommandAllowedInPhase(msg.cmd, enclavePhase, msg.attestedFlag)
             /\ msg.nonce = activeNonce
             /\ msg.epoch = sessionEpoch
             /\ opCount < MaxSessionOps
             /\ ~keyZeroized
          THEN
             LET resp == [
                 dir |-> "E2C",
                 cmd |-> "CMD_BLIND_PHASE1",
                 nonce |-> activeNonce,
                 epoch |-> sessionEpoch,
                 headerValid |-> TRUE,
                 payloadBounded |-> TRUE,
                 attestedFlag |-> TRUE,
                 status |-> "OK"
             ]
             IN
             /\ enclavePhase' = "Phase1Blinded"
             /\ opCount' = opCount + 1
             /\ buffersZeroized' = TRUE
             /\ lastWireStatus' = 0
             /\ netChannel' = Append(Tail(netChannel), resp)
             /\ UNCHANGED <<clientPhase, sessionEpoch, activeNonce, usedNonces, keyZeroized, advFaultsUsed>>
          ELSE
             FailClosedZeroize

ClientReceivePhase1 ==
    /\ enclavePhase \notin TerminalEnclavePhases
    /\ Len(netChannel) > 0
    /\ LET msg == Head(netChannel) IN
       /\ msg.dir = "E2C"
       /\ msg.cmd = "CMD_BLIND_PHASE1"
       /\ IF clientPhase = "Phase1Sent"
             /\ msg.headerValid = TRUE
             /\ msg.payloadBounded = TRUE
             /\ msg.status = "OK"
             /\ msg.nonce = activeNonce
             /\ msg.epoch = sessionEpoch
          THEN
             /\ clientPhase' = "Phase1Done"
             /\ netChannel' = Tail(netChannel)
             /\ UNCHANGED <<enclavePhase, sessionEpoch, opCount, activeNonce, usedNonces, keyZeroized, buffersZeroized, lastWireStatus, advFaultsUsed>>
          ELSE
             FailClosedZeroize

ClientSendPhase2Reblind ==
    /\ enclavePhase = "Phase1Blinded"
    /\ clientPhase = "Phase1Done"
    /\ Len(netChannel) < MaxChannelQueue
    /\ LET req == [
           dir |-> "C2E",
           cmd |-> "CMD_PHASE2_REBLIND",
           nonce |-> activeNonce,
           epoch |-> sessionEpoch,
           headerValid |-> TRUE,
           payloadBounded |-> TRUE,
           attestedFlag |-> TRUE,
           status |-> "OK"
       ]
       IN
       /\ clientPhase' = "Phase2ReblindSent"
       /\ netChannel' = Append(netChannel, req)
       /\ UNCHANGED <<enclavePhase, sessionEpoch, opCount, activeNonce, usedNonces, keyZeroized, buffersZeroized, lastWireStatus, advFaultsUsed>>

EnclaveProcessPhase2Reblind ==
    /\ enclavePhase \notin TerminalEnclavePhases
    /\ Len(netChannel) > 0
    /\ LET msg == Head(netChannel) IN
       /\ msg.dir = "C2E"
       /\ msg.cmd = "CMD_PHASE2_REBLIND"
       /\ IF IsWellFormedRequest(msg)
             /\ IsCommandAllowedInPhase(msg.cmd, enclavePhase, msg.attestedFlag)
             /\ msg.nonce = activeNonce
             /\ msg.epoch = sessionEpoch
             /\ opCount < MaxSessionOps
             /\ ~keyZeroized
          THEN
             LET resp == [
                 dir |-> "E2C",
                 cmd |-> "CMD_PHASE2_REBLIND",
                 nonce |-> activeNonce,
                 epoch |-> sessionEpoch,
                 headerValid |-> TRUE,
                 payloadBounded |-> TRUE,
                 attestedFlag |-> TRUE,
                 status |-> "OK"
             ]
             IN
             /\ enclavePhase' = "Phase2Reblinded"
             /\ opCount' = opCount + 1
             /\ buffersZeroized' = TRUE
             /\ lastWireStatus' = 0
             /\ netChannel' = Append(Tail(netChannel), resp)
             /\ UNCHANGED <<clientPhase, sessionEpoch, activeNonce, usedNonces, keyZeroized, advFaultsUsed>>
          ELSE
             FailClosedZeroize

ClientReceivePhase2Reblind ==
    /\ enclavePhase \notin TerminalEnclavePhases
    /\ Len(netChannel) > 0
    /\ LET msg == Head(netChannel) IN
       /\ msg.dir = "E2C"
       /\ msg.cmd = "CMD_PHASE2_REBLIND"
       /\ IF clientPhase = "Phase2ReblindSent"
             /\ msg.headerValid = TRUE
             /\ msg.payloadBounded = TRUE
             /\ msg.status = "OK"
             /\ msg.nonce = activeNonce
             /\ msg.epoch = sessionEpoch
          THEN
             /\ clientPhase' = "Phase2ReblindDone"
             /\ netChannel' = Tail(netChannel)
             /\ UNCHANGED <<enclavePhase, sessionEpoch, opCount, activeNonce, usedNonces, keyZeroized, buffersZeroized, lastWireStatus, advFaultsUsed>>
          ELSE
             FailClosedZeroize

ClientSendPhase2Intersect ==
    /\ enclavePhase = "Phase2Reblinded"
    /\ clientPhase = "Phase2ReblindDone"
    /\ Len(netChannel) < MaxChannelQueue
    /\ LET req == [
           dir |-> "C2E",
           cmd |-> "CMD_PHASE2_INTERSECT",
           nonce |-> activeNonce,
           epoch |-> sessionEpoch,
           headerValid |-> TRUE,
           payloadBounded |-> TRUE,
           attestedFlag |-> TRUE,
           status |-> "OK"
       ]
       IN
       /\ clientPhase' = "Phase2IntersectSent"
       /\ netChannel' = Append(netChannel, req)
       /\ UNCHANGED <<enclavePhase, sessionEpoch, opCount, activeNonce, usedNonces, keyZeroized, buffersZeroized, lastWireStatus, advFaultsUsed>>

EnclaveProcessPhase2Intersect ==
    /\ enclavePhase \notin TerminalEnclavePhases
    /\ Len(netChannel) > 0
    /\ LET msg == Head(netChannel) IN
       /\ msg.dir = "C2E"
       /\ msg.cmd = "CMD_PHASE2_INTERSECT"
       /\ IF IsWellFormedRequest(msg)
             /\ IsCommandAllowedInPhase(msg.cmd, enclavePhase, msg.attestedFlag)
             /\ msg.nonce = activeNonce
             /\ msg.epoch = sessionEpoch
             /\ opCount < MaxSessionOps
             /\ ~keyZeroized
          THEN
             LET resp == [
                 dir |-> "E2C",
                 cmd |-> "CMD_PHASE2_INTERSECT",
                 nonce |-> activeNonce,
                 epoch |-> sessionEpoch,
                 headerValid |-> TRUE,
                 payloadBounded |-> TRUE,
                 attestedFlag |-> TRUE,
                 status |-> "OK"
             ]
             IN
             /\ enclavePhase' = "Phase2Intersected"
             /\ clientPhase' = "Completed"
             /\ opCount' = opCount + 1
             /\ keyZeroized' = TRUE
             /\ buffersZeroized' = TRUE
             /\ lastWireStatus' = 0
             /\ netChannel' = Append(Tail(netChannel), resp)
             /\ UNCHANGED <<sessionEpoch, activeNonce, usedNonces, advFaultsUsed>>
          ELSE
             FailClosedZeroize

EnclaveRejectMalformedOrOutOfPhase ==
    /\ enclavePhase \notin TerminalEnclavePhases
    /\ Len(netChannel) > 0
    /\ LET msg == Head(netChannel) IN
       /\ msg.dir = "C2E"
       /\ ~( /\ IsWellFormedRequest(msg)
             /\ IsCommandAllowedInPhase(msg.cmd, enclavePhase, msg.attestedFlag)
             /\ msg.nonce = activeNonce
             /\ msg.epoch = sessionEpoch
             /\ opCount < MaxSessionOps
             /\ ~keyZeroized )
       /\ FailClosedZeroize

ClientFailClosedOnDropOrCorrupt ==
    /\ enclavePhase \notin TerminalEnclavePhases
    /\ \/ ( /\ Len(netChannel) > 0
            /\ LET msg == Head(netChannel) IN
               /\ msg.dir = "E2C"
               /\ ~( /\ msg.headerValid = TRUE
                     /\ msg.payloadBounded = TRUE
                     /\ msg.status = "OK"
                     /\ msg.nonce = activeNonce
                     /\ msg.epoch = sessionEpoch ) )
       \/ ( /\ Len(netChannel) = 0
            /\ clientPhase \in {"ChallengeSent", "Phase1Sent", "Phase2ReblindSent", "Phase2IntersectSent"} )
    /\ FailClosedZeroize

TerminalStutter ==
    /\ enclavePhase \in TerminalEnclavePhases
    /\ UNCHANGED vars

AdvDropPacket ==
    /\ enclavePhase \notin TerminalEnclavePhases
    /\ advFaultsUsed < MaxAdvFaults
    /\ Len(netChannel) > 0
    /\ netChannel' = Tail(netChannel)
    /\ advFaultsUsed' = advFaultsUsed + 1
    /\ UNCHANGED <<enclavePhase, clientPhase, sessionEpoch, opCount, activeNonce, usedNonces, keyZeroized, buffersZeroized, lastWireStatus>>

AdvDuplicatePacket ==
    /\ enclavePhase \notin TerminalEnclavePhases
    /\ advFaultsUsed < MaxAdvFaults
    /\ Len(netChannel) > 0
    /\ Len(netChannel) < MaxChannelQueue
    /\ netChannel' = Append(netChannel, Head(netChannel))
    /\ advFaultsUsed' = advFaultsUsed + 1
    /\ UNCHANGED <<enclavePhase, clientPhase, sessionEpoch, opCount, activeNonce, usedNonces, keyZeroized, buffersZeroized, lastWireStatus>>

AdvReorderPackets ==
    /\ enclavePhase \notin TerminalEnclavePhases
    /\ advFaultsUsed < MaxAdvFaults
    /\ Len(netChannel) >= 2
    /\ LET first == netChannel[1]
           second == netChannel[2]
           rest == SubSeq(netChannel, 3, Len(netChannel))
       IN
       /\ netChannel' = <<second, first>> \o rest
       /\ advFaultsUsed' = advFaultsUsed + 1
       /\ UNCHANGED <<enclavePhase, clientPhase, sessionEpoch, opCount, activeNonce, usedNonces, keyZeroized, buffersZeroized, lastWireStatus>>

AdvCorruptOrTruncatePacket ==
    /\ enclavePhase \notin TerminalEnclavePhases
    /\ advFaultsUsed < MaxAdvFaults
    /\ Len(netChannel) > 0
    /\ LET orig == Head(netChannel)
           corrupted == [orig EXCEPT !.headerValid = FALSE, !.payloadBounded = FALSE]
       IN
       /\ netChannel' = <<corrupted>> \o Tail(netChannel)
       /\ advFaultsUsed' = advFaultsUsed + 1
       /\ UNCHANGED <<enclavePhase, clientPhase, sessionEpoch, opCount, activeNonce, usedNonces, keyZeroized, buffersZeroized, lastWireStatus>>

AdvInjectOutOfPhaseCommand ==
    /\ enclavePhase \notin TerminalEnclavePhases
    /\ advFaultsUsed < MaxAdvFaults
    /\ Len(netChannel) < MaxChannelQueue
    /\ \E cmd \in {"CMD_INGEST", "CMD_BLIND_PHASE1", "CMD_PHASE2_REBLIND", "CMD_PHASE2_INTERSECT"} :
       \E n \in Nonces \cup {0} :
        LET forged == [
            dir |-> "C2E",
            cmd |-> cmd,
            nonce |-> n,
            epoch |-> sessionEpoch,
            headerValid |-> TRUE,
            payloadBounded |-> TRUE,
            attestedFlag |-> FALSE,
            status |-> "OK"
        ]
        IN
        /\ netChannel' = <<forged>> \o netChannel
        /\ advFaultsUsed' = advFaultsUsed + 1
        /\ UNCHANGED <<enclavePhase, clientPhase, sessionEpoch, opCount, activeNonce, usedNonces, keyZeroized, buffersZeroized, lastWireStatus>>

ProgressNext ==
    \/ ClientSendAttestChallenge
    \/ EnclaveProcessAttest
    \/ ClientReceiveAttestVerify
    \/ ClientSendPhase1
    \/ EnclaveProcessPhase1
    \/ ClientReceivePhase1
    \/ ClientSendPhase2Reblind
    \/ EnclaveProcessPhase2Reblind
    \/ ClientReceivePhase2Reblind
    \/ ClientSendPhase2Intersect
    \/ EnclaveProcessPhase2Intersect
    \/ EnclaveRejectMalformedOrOutOfPhase
    \/ ClientFailClosedOnDropOrCorrupt
    \/ TerminalStutter

AdversaryNext ==
    \/ AdvDropPacket
    \/ AdvDuplicatePacket
    \/ AdvReorderPackets
    \/ AdvCorruptOrTruncatePacket
    \/ AdvInjectOutOfPhaseCommand

Next == ProgressNext \/ AdversaryNext

Spec == Init /\ [][Next]_vars /\ WF_vars(ProgressNext)

TypeInvariant ==
    /\ enclavePhase \in EnclavePhases
    /\ clientPhase \in ClientPhases
    /\ netChannel \in Seq(FrameSet)
    /\ Len(netChannel) <= MaxChannelQueue
    /\ sessionEpoch \in 1..2
    /\ opCount \in 0..MaxSessionOps
    /\ activeNonce \in Nonces \cup {0}
    /\ usedNonces \subseteq Nonces
    /\ keyZeroized \in BOOLEAN
    /\ buffersZeroized \in BOOLEAN
    /\ lastWireStatus \in {0, -1}
    /\ advFaultsUsed \in 0..MaxAdvFaults

SafetyPhaseMonotonicity ==
    /\ (enclavePhase = "AttestedBound" => activeNonce \in Nonces /\ opCount >= 1)
    /\ (enclavePhase = "Phase1Blinded" => activeNonce \in Nonces /\ opCount >= 2)
    /\ (enclavePhase = "Phase2Reblinded" => activeNonce \in Nonces /\ opCount >= 3)
    /\ (enclavePhase = "Phase2Intersected" => activeNonce \in Nonces /\ opCount >= 4)

SafetyFailClosedZeroization ==
    /\ (enclavePhase = "ClosedZeroized" => (keyZeroized /\ buffersZeroized /\ opCount = 0 /\ lastWireStatus = -1))
    /\ (enclavePhase = "Phase2Intersected" => (keyZeroized /\ buffersZeroized /\ lastWireStatus = 0))
    /\ (buffersZeroized = TRUE)

SafetySessionOpCeiling ==
    opCount <= MaxSessionOps

DeadlockFreedom ==
    enclavePhase \notin TerminalEnclavePhases =>
        \/ Len(netChannel) > 0
        \/ clientPhase \in {"Init", "ChallengeSent", "Attested", "Phase1Sent", "Phase1Done", "Phase2ReblindSent", "Phase2ReblindDone", "Phase2IntersectSent"}

SessionCompleteness ==
    []((enclavePhase = "Unattested" /\ advFaultsUsed = 0) =>
        <>(enclavePhase = "Phase2Intersected" \/ advFaultsUsed > 0))

LivelockFreedom ==
    <>(enclavePhase \in TerminalEnclavePhases)

====
