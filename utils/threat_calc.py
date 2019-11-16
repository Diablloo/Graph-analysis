from networkx import DiGraph


class ThreatCalculator:

    def __init__(self, graph: DiGraph):
        self.graph = graph
        self.visited_nodes = []
        self.nodes_threat = {}

    def calculate_threat_for_node(self, node: str) -> float:
        node_threat = 0
        for u, v in self.graph.out_edges(node):
            if v not in self.visited_nodes:
                self.visited_nodes.append(v)
                node_threat += self.graph[u][v]['weight'] + self.calculate_threat_for_node(v)
        return node_threat

    def calculate_graph_threat(self, device_nodes: list) -> float:
        self.nodes_threat = {}
        threat = 0.
        for node in device_nodes:
            self.visited_nodes = [node]
            tmp_threat = self.calculate_threat_for_node(node)
            self.nodes_threat[node] = tmp_threat
            threat += tmp_threat

        return threat

    def find_best_countermeasure_choice(self, device_nodes: list, vuln_nodes: list) -> (str, float):
        deleted_note_threat_reducion = {}
        base_threat = self.calculate_graph_threat(device_nodes)
        max_reduction = -1
        max_node = ""
        for node in vuln_nodes:
            base_graph = self.graph.copy()
            self.graph.remove_node(node)
            reduction = base_threat - self.calculate_graph_threat(device_nodes)
            deleted_note_threat_reducion[node] = reduction

            if reduction > max_reduction:
                max_reduction = reduction
                max_node = node

            self.graph = base_graph

        return max_node, max_reduction
