import logging
import time

logger = logging.getLogger(__name__)

class QoSRuntime:
    def __init__(self, ml_engine, policy_engine, traffic_processor):
        self.ml = ml_engine
        self.policy = policy_engine
        self.processor = traffic_processor
        # cache for existing decisions to avoid redundant ML calls
        self.decision_cache = {}

    def handle_packet(self, packet):
        """
        Main runtime logic for every incoming packet
        """
        # 1. pre-process packet and extract domain/flow info
        proc_data = self.processor.process_packet(packet)
        if not proc_data:
            return None

        flow_key = self.get_flow_key(packet)
        packet_count = proc_data['flow_packet_count']
        domain = proc_data['domain']

        # 2. decision logic branching
        # Phase A: early flow (TCP handshake stage)
        if packet_count < 10:
            return self.fast_pass(domain, "EARLY_FLOW_HANDSHAKE")

        # Phase B: reuse cached decision for efficiency
        if flow_key in self.decision_cache and packet_count % 50 != 0:
            return self.decision_cache[flow_key]

        # Phase C: perform ML inference
        # extract features (assumes features_cd and features_ab are prepared)
        features_cd = self.extract_features_cd(packet, proc_data)
        features_ab = self.extract_features_ab(packet, proc_data)
        
        ml_result = self.ml.infer(features_cd, features_ab)

        # Phase D: policy decision with metadata context
        metadata = {
            "mapped_domain": domain,
            "flow_packet_count": packet_count
        }
        
        final_decision = self.policy.decide(ml_result, source=domain, metadata=metadata)
        
        # 3. update cache and return
        self.decision_cache[flow_key] = final_decision
        return final_decision

    def fast_pass(self, domain, reason):
        # quickly allow traffic for academic or early stage flows
        priority = "MEDIUM"
        if self.policy.is_academic_domain(domain):
            priority = "HIGH"
        
        return {
            "action": "ALLOW",
            "priority": priority,
            "reason": reason
        }

    def get_flow_key(self, packet):
        # implementation of 5-tuple extraction
        pass

    def extract_features_cd(self, packet, proc_data):
        # prepare CD feature vector for ml engine
        pass

    def extract_features_ab(self, packet, proc_data):
        # prepare AB feature vector for ml engine
        pass