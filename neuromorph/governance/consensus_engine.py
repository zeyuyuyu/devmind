"""Consensus engine implementing Byzantine fault tolerant agreement protocol."""

from typing import List, Set, Dict, Optional
from dataclasses import dataclass
from enum import Enum
import time
import hashlib

class ConsensusState(Enum):
    PROPOSE = 'PROPOSE'
    PREVOTE = 'PREVOTE' 
    PRECOMMIT = 'PRECOMMIT'
    COMMIT = 'COMMIT'

@dataclass
class ConsensusMessage:
    sender: str
    state: ConsensusState
    value: str
    round: int
    timestamp: float
    signature: str

class ConsensusEngine:
    def __init__(self, node_id: str, peers: List[str], f: int):
        self.node_id = node_id
        self.peers = set(peers)
        self.f = f  # Byzantine fault tolerance threshold
        self.round = 0
        self.current_state = ConsensusState.PROPOSE
        self.messages: Dict[int, Set[ConsensusMessage]] = {}
        self.locked_value: Optional[str] = None
        self.decided_value: Optional[str] = None
        
    def broadcast_message(self, value: str) -> ConsensusMessage:
        """Create and broadcast a new consensus message."""
        msg = ConsensusMessage(
            sender=self.node_id,
            state=self.current_state,
            value=value,
            round=self.round,
            timestamp=time.time(),
            signature=self._sign_message(value)
        )
        if self.round not in self.messages:
            self.messages[self.round] = set()
        self.messages[self.round].add(msg)
        return msg

    def _sign_message(self, value: str) -> str:
        """Create cryptographic signature for message."""
        return hashlib.sha256(
            f"{self.node_id}:{value}:{self.round}".encode()
        ).hexdigest()

    def receive_message(self, msg: ConsensusMessage) -> None:
        """Process received consensus message."""
        if msg.sender not in self.peers:
            return
        if msg.round not in self.messages:
            self.messages[msg.round] = set()
        self.messages[msg.round].add(msg)
        self._try_advance_state()

    def _try_advance_state(self) -> None:
        """Attempt to advance consensus state if conditions are met."""
        if self.decided_value:
            return

        round_msgs = self.messages.get(self.round, set())
        state_msgs = {m for m in round_msgs if m.state == self.current_state}

        if len(state_msgs) < 2*self.f + 1:
            return

        if self.current_state == ConsensusState.PROPOSE:
            # Move to prevote if we have enough proposals
            proposed_values = {m.value for m in state_msgs}
            if len(proposed_values) == 1:
                self.locked_value = next(iter(proposed_values))
            self.current_state = ConsensusState.PREVOTE
            self.broadcast_message(self.locked_value or '')

        elif self.current_state == ConsensusState.PREVOTE:
            # Move to precommit if we have enough matching prevotes
            prevote_values = {m.value for m in state_msgs}
            if len(prevote_values) == 1 and '' not in prevote_values:
                self.locked_value = next(iter(prevote_values))
                self.current_state = ConsensusState.PRECOMMIT
                self.broadcast_message(self.locked_value)
            else:
                # Start new round if no consensus
                self.round += 1
                self.current_state = ConsensusState.PROPOSE

        elif self.current_state == ConsensusState.PRECOMMIT:
            # Achieve consensus if we have enough matching precommits
            precommit_values = {m.value for m in state_msgs}
            if len(precommit_values) == 1 and '' not in precommit_values:
                self.decided_value = next(iter(precommit_values))
                self.current_state = ConsensusState.COMMIT
            else:
                # Start new round if no consensus
                self.round += 1
                self.current_state = ConsensusState.PROPOSE

    def get_consensus_result(self) -> Optional[str]:
        """Return the agreed upon value if consensus was reached."""
        return self.decided_value
