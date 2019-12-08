from networkx import MultiDiGraph


class GraphSearcher:

    def __init__(self, graph: MultiDiGraph):
        self.graph = graph
        self.in_edges = []
        self.out_edges = []

    def get_source(self, target):
        for u, v in self.graph.in_edges(target):
            if v == target and u not in self.in_edges:
                self.in_edges.append(u)
                self.get_source(u)

    def get_sources_to_target_node(self, target) -> list:
        self.in_edges = []
        self.get_source(target)
        return self.in_edges
