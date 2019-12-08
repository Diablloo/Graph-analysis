from time import time

from networkx import MultiDiGraph, graph, is_strongly_connected
from networkx.drawing.nx_pydot import write_dot

from utils.graph_search import GraphSearcher
from utils.graph_utils import get_strongly_connected_components, subgraph_criticality, map_component_edges, \
    map_component_inside_edges
from utils.threat_calc import ThreatCalculator


class GraphOptimizer:

    def __init__(self, multiDiGraph: MultiDiGraph):
        # Nx MultiDiGraph used to compute threat
        self.nxGraph = multiDiGraph
        self.previousCopy = multiDiGraph.copy()
        # Threat calculator with an ability to remember threat of node
        self.threat_calc = ThreatCalculator(self.nxGraph)

        self.components_index = 0
        self.graph_threat = 0
        self.strong_components = {}
        self.links_to_strong_components = {}
        self.nodes_threat = {}
        self.strong_components_to_update = set()
        self.vulns = {}
        self.nodes = []
        self.edges = []

        self._init_graph()
        pass

    def _init_graph(self):
        for node in self.nxGraph.nodes:
            self.nodes.append(node)
            self.vulns[node] = []

        for edge in self.nxGraph.edges:
            self.edges.append(edge)
            if edge[2] not in self.vulns[edge[1]]:
                self.vulns[edge[1]].append(edge[2])
        pass

    def save_graph(self, name):
        write_dot(self.nxGraph, name)

    def add_node(self):
        pass

    def add_edge(self, edge: list):
        """
        add edge to nx graph
        :param edge: taple of source, destination and cve
        :return:
        """
        self.nxGraph.add_edge(edge[0], edge[1], edge[2], cve=edge[2])

    def remove_node(self, node):
        """
        Remove node from nx graph
        :return:
        """
        self.nxGraph.remove_node(node)
        self.nodes.remove(node)
        pass

    def remove_edge(self, edge: list):
        """
        remove edge from nx graph
        :return:
        """
        self.nxGraph.remove_edge(edge[0], edge[1], edge[2])

    def remove_cve(self, cve):
        for edge in self.edges:
            if edge[2] == cve:
                self.remove_edge(edge)

    def _link_nodes_to_component(self, index: int):
        # hash table, now we can find out, is current node in strong component or not
        for node in self.strong_components[index]['nodes']:
            self.links_to_strong_components[node] = index

    def _integrate_strong_component_to_graph(self, index: int):
        component_name = f"strong_component_{index}"

        # Create new node
        # self.nxGraph.add_node(component_name, weight=self.strong_components[index]['threat'])
        # Add all previous links to this node
        edges_in, edges_out = map_component_edges(self.nxGraph, self.strong_components[index]['nodes'])
        edges_inside = map_component_inside_edges(self.nxGraph, self.strong_components[index]['nodes'])

        self.strong_components[index]['edges_inside'] = edges_inside
        self.strong_components[index]['edges_in'] = edges_in
        self.strong_components[index]['edges_out'] = edges_out

    def _get_strong_components_threat(self):
        threat = 0.
        for key, value in self.strong_components:
            threat += value['subgraph_threat']

        return threat

    def _extend_nodes_threat(self, new_nodes_threat):
        for key, value in new_nodes_threat.items():
            self.nodes_threat[key] = value

    def _add_strong_component(self, strong_component_data: dict):
        # need to get component by hash index, so used the identificator
        self.strong_components[self.components_index] = strong_component_data

        self._link_nodes_to_component(self.components_index)
        self._integrate_strong_component_to_graph(self.components_index)
        self.components_index += 1

    def create_optimized_component(self, component: list, criticality: float, threat: float):
        # Seems that i don't need to mark edges here, because i can restore them from MultiDiGraph
        # TODO:Check, do i really need to keep list of nodes in component_data
        component_data = {'threat': threat, 'criticality': criticality,
                          'subgraph_threat': threat * len(component), 'nodes': component}
        self._add_strong_component(component_data)

    def _update_strong_component(self, component_id: int):
        """
        Updates strong component after cve removal
        :param component_id:
        :return:
        """
        component = self.strong_components[component_id]
        subgraph = self.nxGraph.subgraph(component['nodes'])
        is_still_strong = is_strongly_connected(subgraph)

        if not is_still_strong:
            # Remove previous component and get new if we can
            self.strong_components.pop(component_id, None)
            # Find new components
            strong_components_nodes = get_strongly_connected_components(subgraph)
            # Add new components to list of components
            for component in strong_components_nodes:
                self._workout_strong_component(component)

    def _update_component_params(self, component_id: int):
        """
        Update parameters of components such as criticality and threat
        :param component_id:
        :return:
        """
        # When cve is deleted, component can be deleted, or just change the threat
        component = self.strong_components[component_id]
        component_threat = self.threat_calc.calculate_graph_threat([component['nodes'][0]])
        # Pre computed threat for all strong component nodes
        for node in component:
            self.nodes_threat[node] = component_threat

        component['threat'] = component_threat
        component['subgraph_threat'] = component_threat * len(component['nodes'])

    def _update_nodes_threat(self, node_list: list):
        self.strong_components_to_update = set()
        for node in node_list:
            if node in self.links_to_strong_components:
                self.strong_components_to_update.add(self.links_to_strong_components[node])
            else:
                self.nodes_threat[node] = 0.

    def _workout_strong_component(self, component):
        component_criticality = subgraph_criticality(self.nxGraph, component, component[0])
        # we can take only 1 node from strong connected component and multiply it on component size
        # TODO: may be i should speed up the threat counting by using memorized_calculate_threat_for_node???
        component_threat = self.threat_calc.calculate_graph_threat([component[0]])
        # Pre computed threat for all strong component nodes
        for node in component:
            self.nodes_threat[node] = component_threat

        self.create_optimized_component(component, component_criticality, component_threat)

    def _update_after_countermeasure(self, target):
        searcher = GraphSearcher(self.previousCopy)
        nodes_to_target = searcher.get_sources_to_target_node(target)

        # Update strong components
        if target in self.links_to_strong_components:
            self._update_strong_component(self.links_to_strong_components[target])

        # Update nodes and strong component threats
        self._update_nodes_threat(nodes_to_target)


    def find_countermeasure(self):
        calc = ThreatCalculator(self.nxGraph, self.strong_components, self.links_to_strong_components)
        # TODO: make own countermeasure calculation based on threat saving mechanisms
        cve, new_threat, target = calc.find_best_countermeasure_choice(self.nodes, self.vulns)
        # TODO: may be I should return full list of edges to avoid searching for them again
        # Remove cve edges to {target}
        self.remove_cve(cve)
        # optimize after deletion
        # self._update_after_countermeasure(target)

        threat = self.compute_threat()
        return cve, new_threat

    def intelligence_find_countermeasure(self):
        deleted_vuln_threat_reducion = {}
        base_threat = self.compute_threat()
        max_reduction = -1
        max_cve = ""
        # tmp_graph = self.graph.copy()
        #TODO: change score counting from depth to starter
        for node in self.vulns.keys():
            for vuln in self.vulns[node]:
                base_graph = self.nxGraph.copy()
                edges_to_delete = []
                for u, v, attrs in self.nxGraph.in_edges(node, data=True):
                    if attrs['cve'] == vuln:
                        edges_to_delete.append((u,v))
                for u,v in edges_to_delete:
                    self.nxGraph.remove_edge(u, v, key=vuln)
                # Optimization step
                self._update_after_countermeasure(node)
                # Basic search
                reduction = base_threat - self.compute_threat()
                deleted_vuln_threat_reducion[vuln] = reduction

                if reduction > max_reduction:
                    max_reduction = reduction
                    max_cve = vuln
                    target = node

                self.nxGraph = base_graph

        return max_cve, base_threat - max_reduction, target
    def compute_threat(self):
        """
        After optimization we know the threat of strong components subgraphs and we destroyed the circles
        so we can start remembering the threat of current nodes
        :return:
        """
        threat = 0.
        compute_node_list = []
        # Update Threat of strong component
        for component in self.strong_components_to_update:
            self._update_component_params(component)
        # Threat of nodes that dont belong to strong components
        calc = ThreatCalculator(self.nxGraph, self.strong_components, self.links_to_strong_components)
        # Calculate threat only for updated paths
        # So if we computed it before and it didn't change, so we can use it again
        for node in self.nodes:
            if node not in self.nodes_threat:
                compute_node_list.append(node)
            else:
                threat += self.nodes_threat[node]
        # Now we compute threat only for NEWLY changed pathes
        graph_threat = calc.memorized_calculate_graph_threat(compute_node_list)
        # Now we need to summarize it with strong components threat
        for component in self.strong_components.values():
            graph_threat += component['subgraph_threat']

        calculated_nodes_threat = self.threat_calc.get_nodes_threat()
        self._extend_nodes_threat(calculated_nodes_threat)

        return graph_threat

    def optimize(self):
        start = time()
        strong_components_nodes = get_strongly_connected_components(self.nxGraph)
        components_detection = time()
        #Precount
        # self.graph_threat = ThreatCalculator(self.nxGraph).calculate_graph_threat(self.nodes)
        for component in strong_components_nodes:
            self._workout_strong_component(component)

        print(f"Constructed strong components in {time() - start} seconds")


