from networkx import DiGraph


class ThreatCalculator:

    def __init__(self, graph: DiGraph):
        self.graph = graph.copy()
        self.visited_nodes = []
        self.nodes_threat = {}

    def calculate_threat_for_node(self, node: str) -> float:
        self.visited_nodes.append(node)
        node_threat = self.graph.nodes[node]['weight']
        for u, v in self.graph.out_edges(node):
            if v not in self.visited_nodes:
                # self.visited_nodes.append(v)
                # node_threat += self.graph[u][v]['weight'] + self.calculate_threat_for_node(v)
                node_threat += self.calculate_threat_for_node(v)
        return node_threat

    def calculate_graph_threat(self, device_nodes: list) -> float:
        self.nodes_threat = {}
        threat = 0.
        for node in device_nodes:
            self.visited_nodes = []
            tmp_threat = self.calculate_threat_for_node(node)
            self.nodes_threat[node] = tmp_threat
            threat += tmp_threat

        return threat

    def find_best_countermeasure_choice(self, device_nodes: list, node_vulns: dict) -> (str, float):
        deleted_vuln_threat_reducion = {}
        base_threat = self.calculate_graph_threat(device_nodes)
        max_reduction = -1
        max_cve = ""
        # tmp_graph = self.graph.copy()
        #TODO: change score counting from depth to starter
        for node in node_vulns.keys():
            for vuln in node_vulns[node]:
                base_graph = self.graph.copy()
                edges_to_delete = []
                for u, v, attrs in self.graph.in_edges(node, data=True):
                    if attrs['cve'] == vuln:
                        edges_to_delete.append((u,v))
                for u,v in edges_to_delete:
                    self.graph.remove_edge(u,v,key=vuln)

                reduction = base_threat - self.calculate_graph_threat(device_nodes)
                deleted_vuln_threat_reducion[vuln] = reduction

                if reduction > max_reduction:
                    max_reduction = reduction
                    max_cve = vuln

                self.graph = base_graph

        return max_cve, base_threat - max_reduction
