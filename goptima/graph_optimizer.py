from networkx import MultiDiGraph, graph

from utils.graph_utils import get_strongly_connected_components, subgraph_criticality, map_component_edges
from utils.threat_calc import ThreatCalculator


class GraphOptimizer:

    def __init__(self, multiDiGraph: MultiDiGraph):
        self.nxGraph = multiDiGraph
        self.components_index = 0
        self.strong_components = {}
        self.links_to_strong_components = {}
        self.nodes = []
        self.edges = []
        pass

    def compute_threat(self):
        pass

    def add_node(self):
        pass

    def add_edge(self, edge: list):
        """
        add edge to nx graph
        :param edge: taple of source, destination and cve
        :return:
        """
        self.nxGraph.add_edge(edge[0], edge[1], edge[2], cve=edge[2])

    def remove_node(self):
        pass

    def remove_edge(self):
        pass

    def _link_nodes_to_component(self, index: int):
        # hash table, now we can find out, is current node in strong component or not
        for node in self.strong_components[index]['nodes']:
            self.links_to_strong_components[node] = index

    def _integrate_strong_component_to_graph(self, index: int):
        component_name = f"strong_component_{index}"

        # Create new node
        self.nxGraph.add_node(component_name, weight=self.strong_components[index])
        # Add all previous links to this node
        edges_in, edges_out = map_component_edges(self.strong_components[index]['nodes'])

        for edge in edges_in + edges_out:
            self.add_edge(edge)

    def _add_strong_component(self, strong_component_data: dict):
        # need to get component by hash index, so used the identificator
        self.strong_components[self.components_index] = strong_component_data

        self._link_nodes_to_component(self.components_index)
        self._integrate_strong_component_to_graph(self.components_index)
        self.strong_components += 1

    def create_optimized_component(self, component: list, criticality: float, threatness: float):
        # Seems that i don't need to mark edges here, because i can restore them from MultiDiGraph
        # TODO:Check, do i really need to keep list of nodes in component_data
        component_data = {'threatness': threatness, 'criticality': criticality, 'nodes': component}
        self._add_strong_component(component_data)


    def optimize(self):
        self.strong_components = get_strongly_connected_components(self.nxGraph)
        for component in self.strong_components:
            # we can count criticality from any node
            component_criticality = subgraph_criticality(self.nxGraph, component, component[0])

            # we can take only 1 node from strong connected component and multiply it on component size
            component_threatness = len(component) * (ThreatCalculator(self.nxGraph)
                                                     .calculate_threat_for_node(component[0]))
            self.create_optimized_component(component, component_criticality, component_threatness)


        # when all components are registered we can make new graph, changing those components to one node


