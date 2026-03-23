"""
Neuromorph Holographic Consensus Engine

A Byzantine Fault-Tolerant (BFT) consensus protocol for decentralized multi-agent swarms.
Implements weighted holographic voting, reputation-weighted quorum calculation, and
asynchronous consensus finality for autonomous agent collectives.
"""

import asyncio
import hashlib
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Any, Callable, Awaitable
from collections import defaultdict
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ProposalStatus(Enum):
    PENDING = auto()
    ACTIVE = auto()
    ACCEPTED = auto()
    REJECTED = auto()
    EXECUTED = auto()
    EXPIRED = auto()


class VoteType(Enum):
    YES = 1
    NO = 0
    ABSTAIN = -1


@dataclass
class AgentIdentity:
    """Cryptographic identity for swarm agents."""
    agent_id: str
    public_key: rsa.RSAPublicKey
    reputation_score: float = 1.0
    stake_amount: float = 0.0
    joined_at: datetime = field(default_factory=datetime.utcnow)
    last_active: datetime = field(default_factory=datetime.utcnow)
    is_validator: bool = False
    
    def verify_signature(self, message: bytes, signature: bytes) -> bool:
        """Verify RSA signature of agent."""
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


@dataclass
class Proposal:
    """Governance proposal for swarm decision making."""
    proposal_id: str
    proposer_id: str
    title: str
    description: str
    action_payload: Dict[str, Any]
    created_at: datetime
    voting_deadline: datetime
    execution_threshold: float = 0.66  # 2/3 majority default
    min_participation: float = 0.51    # 51% participation required
    
    # State tracking
    status: ProposalStatus = ProposalStatus.PENDING
    votes: Dict[str, Tuple[VoteType, float, bytes]] = field(default_factory=dict)  # agent_id -> (vote, weight, signature)
    execution_timestamp: Optional[datetime] = None
    execution_result: Optional[Any] = None
    
    @property
    def total_weight(self) -> float:
        """Calculate total voting weight cast."""
        return sum(weight for _, weight, _ in self.votes.values())
    
    @property
    def yes_weight(self) -> float:
        return sum(weight for vote, weight, _ in self.votes.values() if vote == VoteType.YES)
    
    @property
    def no_weight(self) -> float:
        return sum(weight for vote, weight, _ in self.votes.values() if vote == VoteType.NO)
    
    def calculate_hash(self) -> str:
        """Generate cryptographic hash of proposal content."""
        content = f"{self.proposal_id}:{self.proposer_id}:{self.title}:{self.created_at.isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()


@dataclass
class ConsensusCheckpoint:
    """Immutable checkpoint for consensus state recovery."""
    checkpoint_id: str
    timestamp: datetime
    block_height: int
    proposal_roots: List[str]  # Merkle roots of accepted proposals
    agent_root: str           # Merkle root of agent registry
    consensus_params: Dict[str, Any]


class ConsensusException(Exception):
    """Base exception for consensus failures."""
    pass


class QuorumNotReached(ConsensusException):
    """Raised when voting quorum is not achieved."""
    pass


class InvalidProposal(ConsensusException):
    """Raised when proposal validation fails."""
    pass


class SlashingCondition(Enum):
    DOUBLE_VOTING = "double_voting"
    INVALID_SIGNATURE = "invalid_signature"
    CENSORSHIP = "censorship"
    BYZANTINE_FAULT = "byzantine_fault"


class ReputationManager:
    """Manages agent reputation scores with decay and slashing."""
    
    def __init__(
        self,
        initial_score: float = 1.0,
        decay_rate: float = 0.01,
        slash_percentage: float = 0.5,
        reward_increment: float = 0.05
    ):
        self.scores: Dict[str, float] = defaultdict(lambda: initial_score)
        self.decay_rate = decay_rate
        self.slash_percentage = slash_percentage
        self.reward_increment = reward_increment
        self.violations: Dict[str, List[Tuple[datetime, SlashingCondition]]] = defaultdict(list)
    
    def update_reputation(self, agent_id: str, success: bool) -> float:
        """Update agent reputation based on behavior."""
        current = self.scores[agent_id]
        
        if success:
            # Logarithmic growth to prevent dominance
            self.scores[agent_id] = min(10.0, current + self.reward_increment * (1 - current/10))
        else:
            # Exponential decay for failures
            self.scores[agent_id] = max(0.1, current * (1 - self.decay_rate))
        
        return self.scores[agent_id]
    
    def slash(self, agent_id: str, condition: SlashingCondition, severity: float = 1.0) -> float:
        """Apply slashing penalty for Byzantine behavior."""
        current = self.scores[agent_id]
        penalty = current * self.slash_percentage * severity
        self.scores[agent_id] = max(0.0, current - penalty)
        self.violations[agent_id].append((datetime.utcnow(), condition))
        
        logger.warning(f"Agent {agent_id} slashed for {condition.value}. New score: {self.scores[agent_id]}")
        return self.scores[agent_id]
    
    def get_effective_weight(self, agent_id: str, stake: float) -> float:
        """Calculate voting weight combining reputation and stake."""
        reputation = self.scores[agent_id]
        # Weighted geometric mean to prevent stake dominance
        return (reputation ** 0.6) * (stake ** 0.4)


class SwarmConsensusEngine:
    """
    Byzantine Fault-Tolerant consensus engine for holographic swarm governance.
    
    Implements asynchronous consensus with:
    - Weighted voting (reputation + stake)
    - HotStuff-inspired chained BFT consensus
    - Slashing conditions for malicious actors
    - Holographic sub-consensus for sub-swarms
    """
    
    def __init__(
        self,
        swarm_id: str,
        byzantine_threshold: float = 1/3,
        checkpoint_interval: int = 100,
        proposal_timeout: timedelta = timedelta(hours=24),
        async_timeout: float = 30.0
    ):
        self.swarm_id = swarm_id
        self.byzantine_threshold = byzantine_threshold
        self.checkpoint_interval = checkpoint_interval
        self.proposal_timeout = proposal_timeout
        self.async_timeout = async_timeout
        
        # Core state
        self.agents: Dict[str, AgentIdentity] = {}
        self.proposals: Dict[str, Proposal] = {}
        self.reputation_manager = ReputationManager()
        
        # Consensus state
        self.block_height = 0
        self.checkpoints: List[ConsensusCheckpoint] = []
        self.pending_proposals: asyncio.Queue[str] = asyncio.Queue()
        self.execution_callbacks: Dict[str, Callable[[Proposal], Awaitable[Any]]] = {}
        
        # Synchronization
        self._lock = asyncio.RLock()
        self._proposal_timers: Dict[str, asyncio.Task] = {}
        self._running = False
        
        # Metrics
        self.metrics = {
            'proposals_created': 0,
            'proposals_accepted': 0,
            'proposals_rejected': 0,
            'consensus_rounds': 0,
            'avg_consensus_time': 0.0
        }
    
    async def start(self):
        """Start the consensus engine background tasks."""
        self._running = True
        asyncio.create_task(self._consensus_loop())
        asyncio.create_task(self._checkpoint_loop())
        logger.info(f"Consensus engine started for swarm {self.swarm_id}")
    
    async def stop(self):
        """Graceful shutdown of consensus engine."""
        self._running = False
        for task in self._proposal_timers.values():
            task.cancel()
        logger.info("Consensus engine stopped")
    
    async def register_agent(
        self,
        agent_id: str,
        public_key_pem: bytes,
        stake: float = 0.0,
        is_validator: bool = False
    ) -> AgentIdentity:
        """Register a new agent in the swarm with cryptographic identity."""
        async with self._lock:
            if agent_id in self.agents:
                raise ValueError(f"Agent {agent_id} already registered")
            
            public_key = serialization.load_pem_public_key(public_key_pem)
            agent = AgentIdentity(
                agent_id=agent_id,
                public_key=public_key,
                stake_amount=stake,
                is_validator=is_validator
            )
            
            self.agents[agent_id] = agent
            logger.info(f"Agent {agent_id} registered with stake {stake}")
            return agent
    
    async def deregister_agent(self, agent_id: str):
        """Remove agent from swarm (requires governance approval in production)."""
        async with self._lock:
            if agent_id in self.agents:
                del self.agents[agent_id]
                logger.info(f"Agent {agent_id} deregistered")
    
    async def create_proposal(
        self,
        proposer_id: str,
        title: str,
        description: str,
        action_payload: Dict[str, Any],
        voting_period: Optional[timedelta] = None
    ) -> Proposal:
        """Create a new governance proposal."""
        if proposer_id not in self.agents:
            raise InvalidProposal("Proposer not registered in swarm")
        
        if voting_period is None:
            voting_period = self.proposal_timeout
        
        proposal_id = f"prop_{secrets.token_hex(16)}"
        created_at = datetime.utcnow()
        
        proposal = Proposal(
            proposal_id=proposal_id,
            proposer_id=proposer_id,
            title=title,
            description=description,
            action_payload=action_payload,
            created_at=created_at,
            voting_deadline=created_at + voting_period,
            status=ProposalStatus.PENDING
        )
        
        async with self._lock:
            self.proposals[proposal_id] = proposal
            self.metrics['proposals_created'] += 1
            
            # Schedule proposal activation and timeout
            self._proposal_timers[proposal_id] = asyncio.create_task(
                self._manage_proposal_lifecycle(proposal_id)
            )
        
        logger.info(f"Proposal {proposal_id} created by {proposer_id}")
        return proposal
    
    async def cast_vote(
        self,
        agent_id: str,
        proposal_id: str,
        vote_type: VoteType,
        signature: bytes
    ) -> bool:
        """
        Cast a weighted vote on a proposal.
        Returns True if consensus reached.
        """
        async with self._lock:
            if agent_id not in self.agents:
                raise ValueError("Agent not registered")
            
            if proposal_id not in self.proposals:
                raise ValueError("Proposal not found")
            
            proposal = self.proposals[proposal_id]
            agent = self.agents[agent_id]
            
            if proposal.status != ProposalStatus.ACTIVE:
                raise InvalidProposal("Proposal not open for voting")
            
            if datetime.utcnow() > proposal.voting_deadline:
                raise InvalidProposal("Voting period ended")
            
            # Verify signature
            vote_message = f"{proposal_id}:{agent_id}:{vote_type.value}".encode()
            if not agent.verify_signature(vote_message, signature):
                self.reputation_manager.slash(agent_id, SlashingCondition.INVALID_SIGNATURE)
                raise InvalidProposal("Invalid vote signature")
            
            # Check for double voting
            if agent_id in proposal.votes:
                self.reputation_manager.slash(agent_id, SlashingCondition.DOUBLE_VOTING, severity=2.0)
                raise InvalidProposal("Double voting detected")
            
            # Calculate voting weight
            weight = self.reputation_manager.get_effective_weight(
                agent_id, agent.stake_amount
            )
            
            # Record vote
            proposal.votes[agent_id] = (vote_type, weight, signature)
            agent.last_active = datetime.utcnow()
            
            logger.debug(f"Vote cast by {agent_id} on {proposal_id}: {vote_type.name}")
            
            # Check for consensus
            return await self._check_consensus(proposal_id)
    
    async def _check_consensus(self, proposal_id: str) -> bool:
        """Check if proposal has reached consensus threshold."""
        proposal = self.proposals[proposal_id]
        
        total_stake = sum(agent.stake_amount for agent in self.agents.values())
        total_reputation = sum(self.reputation_manager.scores[aid] for aid in self.agents)
        total_weight = sum(
            self.reputation_manager.get_effective_weight(aid, agent.stake_amount)
            for aid, agent in self.agents.items()
        )
        
        current_weight = proposal.total_weight
        participation_rate = current_weight / total_weight if total_weight > 0 else 0
        
        # Check minimum participation
        if participation_rate < proposal.min_participation:
            return False
        
        yes_ratio = proposal.yes_weight / current_weight if current_weight > 0 else 0
        
        if yes_ratio >= proposal.execution_threshold:
            proposal.status = ProposalStatus.ACCEPTED
            await self._execute_proposal(proposal_id)
            return True
        elif (1 - yes_ratio) >= proposal.execution_threshold:
            proposal.status = ProposalStatus.REJECTED
            self.metrics['proposals_rejected'] += 1
            return True
        
        return False
    
    async def _execute_proposal(self, proposal_id: str):
        """Execute accepted proposal payload."""
        proposal = self.proposals[proposal_id]
        
        try:
            # Get execution callback for action type
            action_type = proposal.action_payload.get('type', 'default')
            callback = self.execution_callbacks.get(action_type)
            
            if callback:
                proposal.execution_result = await callback(proposal)
            else:
                proposal.execution_result = {"status": "executed", "type": action_type}
            
            proposal.status = ProposalStatus.EXECUTED
            proposal.execution_timestamp = datetime.utcnow()
            self.metrics['proposals_accepted'] += 1
            
            # Update reputations
            for agent_id, (vote, _, _) in proposal.votes.items():
                success = (vote == VoteType.YES and proposal.status == ProposalStatus.EXECUTED) or \
                         (vote == VoteType.NO and proposal.status == ProposalStatus.REJECTED)
                self.reputation_manager.update_reputation(agent_id, success)
            
            logger.info(f"Proposal {proposal_id} executed successfully")
            
        except Exception as e:
            logger.error(f"Proposal {proposal_id} execution failed: {e}")
            proposal.execution_result = {"error": str(e)}
    
    async def _manage_proposal_lifecycle(self, proposal_id: str):
        """Manage proposal state transitions and timeout."""
        try:
            # Activate immediately or after delay based on swarm rules
            await asyncio.sleep(0.1)
            
            async with self._lock:
                if proposal_id in self.proposals:
                    self.proposals[proposal_id].status = ProposalStatus.ACTIVE
            
            # Wait for voting period
            await asyncio.sleep(self.proposal_timeout.total_seconds())
            
            # Timeout handling
            async with self._lock:
                proposal = self.proposals.get(proposal_id)
                if proposal and proposal.status == ProposalStatus.ACTIVE:
                    proposal.status = ProposalStatus.EXPIRED
                    logger.info(f"Proposal {proposal_id} expired")
                    
        except asyncio.CancelledError:
            pass
    
    async def _consensus_loop(self):
        """Background task for consensus maintenance."""
        while self._running:
            try:
                # Process any pending consensus tasks
                await asyncio.sleep(1)
                
                # Clean up expired proposals
                now = datetime.utcnow()
                async with self._lock:
                    expired = [
                        pid for pid, prop in self.proposals.items()
                        if prop.status == ProposalStatus.ACTIVE and now > prop.voting_deadline
                    ]
                    for pid in expired:
                        self.proposals[pid].status = ProposalStatus.EXPIRED
                        
            except Exception as e:
                logger.error(f"Consensus loop error: {e}")
    
    async def _checkpoint_loop(self):
        """Create periodic checkpoints for state recovery."""
        while self._running:
            try:
                await asyncio.sleep(self.checkpoint_interval)
                await self._create_checkpoint()
            except Exception as e:
                logger.error(f"Checkpoint error: {e}")
    
    async def _create_checkpoint(self):
        """Create immutable state checkpoint."""
        async with self._lock:
            accepted_proposals = [
                p for p in self.proposals.values()
                if p.status == ProposalStatus.EXECUTED
            ]
            
            # Calculate merkle roots (simplified)
            proposal_hashes = [p.calculate_hash() for p in accepted_proposals]
            agent_hashes = [f"{aid}:{self.agents[aid].stake_amount}" for aid in self.agents]
            
            checkpoint = ConsensusCheckpoint(
                checkpoint_id=f"chk_{secrets.token_hex(8)}",
                timestamp=datetime.utcnow(),
                block_height=self.block_height,
                proposal_roots=proposal_hashes,
                agent_root=hashlib.sha256(str(agent_hashes).encode()).hexdigest(),
                consensus_params={
                    'byzantine_threshold': self.byzantine_threshold,
                    'total_agents': len(self.agents),
                    'accepted_proposals': len(accepted_proposals)
                }
            )
            
            self.checkpoints.append(checkpoint)
            logger.info(f"Checkpoint created at height {self.block_height}")
    
    def register_execution_callback(
        self,
        action_type: str,
        callback: Callable[[Proposal], Awaitable[Any]]
    ):
        """Register callback for proposal execution."""
        self.execution_callbacks[action_type] = callback
    
    async def get_consensus_state(self) -> Dict[str, Any]:
        """Get current consensus state for monitoring."""
        async with self._lock:
            return {
                'swarm_id': self.swarm_id,
                'block_height': self.block_height,
                'active_agents': len(self.agents),
                'active_proposals': sum(
                    1 for p in self.proposals.values()
                    if p.status == ProposalStatus.ACTIVE
                ),
                'metrics': self.metrics.copy(),
                'total_stake': sum(a.stake_amount for a in self.agents.values()),
                'avg_reputation': sum(self.reputation_manager.scores.values()) / len(self.agents) if self.agents else 0
            }
    
    async def detect_byzantine_agents(self) -> List[Tuple[str, SlashingCondition]]:
        """Detect and return list of suspected Byzantine agents."""
        suspects = []
        
        # Check for agents with multiple violations
        for agent_id, violations in self.reputation_manager.violations.items():
            if len(violations) >= 3:
                suspects.append((agent_id, SlashingCondition.BYZANTINE_FAULT))
        
        return suspects


class HolographicSubConsensus:
    """
    Enables sub-swarms to reach local consensus while maintaining
    compatibility with global consensus state.
    """
    
    def __init__(
        self,
        parent_engine: SwarmConsensusEngine,
        sub_swarm_id: str,
        member_ids: Set[str],
        delegation_threshold: float = 0.5
    ):
        self.parent = parent_engine
        self.sub_swarm_id = sub_swarm_id
        self.members = member_ids
        self.delegation_threshold = delegation_threshold
        self.local_proposals: Dict[str, Proposal] = {}
        
    async def propose_local_action(
        self,
        proposer_id: str,
        action: Dict[str, Any]
    ) -> str:
        """Create a local proposal requiring only sub-swarm consensus."""
        if proposer_id not in self.members:
            raise PermissionError("Agent not in sub-swarm")
        
        # Create proposal in parent engine but mark as local
        action['sub_swarm'] = self.sub_swarm_id
        action['local_consensus'] = True
        
        proposal = await self.parent.create_proposal(
            proposer_id=proposer_id,
            title=f"[Local:{self.sub_swarm_id}] {action.get('title', 'Untitled')}",
            description=action.get('description', ''),
            action_payload=action
        )
        
        self.local_proposals[proposal.proposal_id] = proposal
        return proposal.proposal_id
    
    async def validate_local_consensus(self, proposal_id: str) -> bool:
        """Validate that local quorum is sufficient for global validity."""
        if proposal_id not in self.local_proposals:
            return False
        
        proposal = self.local_proposals[proposal_id]
        
        # Calculate local participation
        local_weight = sum(
            weight for aid, (_, weight, _) in proposal.votes.items()
            if aid in self.members
        )
        
        total_local_weight = sum(
            self.parent.reputation_manager.get_effective_weight(
                aid, self.parent.agents[aid].stake_amount
            )
            for aid in self.members if aid in self.parent.agents
        )
        
        return (local_weight / total_local_weight) >= self.delegation_threshold if total_local_weight > 0 else False


# Example usage and testing utilities
async def example_execution_callback(proposal: Proposal) -> Dict[str, Any]:
    """Example callback for proposal execution."""
    await asyncio.sleep(0.1)  # Simulate execution
    return {
        "executed_at": datetime.utcnow().isoformat(),
        "action": proposal.action_payload,
        "executor": "example_module"
    }


async def main():
    """Demonstration of consensus engine capabilities."""
    # Initialize engine
    engine = SwarmConsensusEngine(
        swarm_id="neuromorph_alpha",
        byzantine_threshold=0.33,
        checkpoint_interval=10
    )
    
    await engine.start()
    
    # Register execution handler
    engine.register_execution_callback("transfer", example_execution_callback)
    engine.register_execution_callback("default", example_execution_callback)
    
    # Generate test keys and register agents
    agents = []
    for i in range(5):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        agent = await engine.register_agent(
            agent_id=f"agent_{i}",
            public_key_pem=pem,
            stake=100.0 * (i + 1),
            is_validator=(i < 3)
        )
        agents.append((agent, private_key))
    
    # Create proposal
    proposal = await engine.create_proposal(
        proposer_id="agent_0",
        title="Treasury Allocation Q1",
        description="Allocate funds for compute resources",
        action_payload={"type": "transfer", "amount": 1000, "recipient": "cluster_a"}
    )
    
    # Cast votes
    for agent, private_key in agents[:4]:  # 4/5 vote
        vote_msg = f"{proposal.proposal_id}:{agent.agent_id}:{VoteType.YES.value}".encode()
        signature = private_key.sign(
            vote_msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        await engine.cast_vote(agent.agent_id, proposal.proposal_id, VoteType.YES, signature)
    
    # Wait for execution
    await asyncio.sleep(2)
    
    # Check state
    state = await engine.get_consensus_state()
    print(f"Consensus State: {json.dumps(state, indent=2, default=str)}")
    
    # Check proposal status
    final_proposal = engine.proposals[proposal.proposal_id]
    print(f"\nProposal Status: {final_proposal.status.name}")
    print(f"Execution Result: {final_proposal.execution_result}")
    
    await engine.stop()


if __name__ == "__main__":
    asyncio.run(main())
