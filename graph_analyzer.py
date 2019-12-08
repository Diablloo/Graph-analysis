from time import time

import networkx as nx
import matplotlib.pyplot as plt
# import pygraphviz
from networkx import MultiDiGraph, maximum_branching, maximum_spanning_arborescence
from networkx.drawing.nx_pydot import write_dot

from utils.graph_utils import generate_graph, get_strongly_connected_components, map_component_edges, \
    subgraph_threat, subgraph_criticality
from utils.http_build_graph import GraphVisualizer
from utils.threat_calc import ThreatCalculator
from goptima.graph_optimizer import GraphOptimizer

graph = nx.DiGraph()
device_nodes_list = ['start', '1_192.168.0.100', '1_192.168.0.119', '1_10.23.0.1', '1_10.23.0.5', '2_192.168.0.100',
                     '1_192.168.0.102', '1_192.168.0.111', '1_223.0.5.98']
vuln_nodes_list = ['1_CVE_1', '2_CVE_1', '3_CVE_1', '1_CVE_2', '1_CVE_3', '1_CVE_4', '2_CVE_4', '1_CVE_5']

device_to_vulns = [('start', '1_CVE_5', 0), ('start', '1_CVE_1', 0), ('start', '2_CVE_1', 0),
                   ('1_192.168.0.100', '1_CVE_2', 0), ('1_192.168.0.100', '2_CVE_1', 0),
                   ('1_192.168.0.119', '1_CVE_2', 0), ('1_192.168.0.119', '1_CVE_1', 0),
                   ('1_10.23.0.1', '1_CVE_3', 0),
                   ('1_10.23.0.5', '1_CVE_4', 0), ('1_10.23.0.5', '3_CVE_1', 0), ('1_10.23.0.5', '2_CVE_4', 0),
                   ('2_192.168.0.100', '3_CVE_1', 0), ('2_192.168.0.100', '2_CVE_4', 0),
                   ('1_192.168.0.102', '1_CVE_4', 0), ('1_192.168.0.102', '2_CVE_4', 0),
                   ('1_192.168.0.111', '1_CVE_4', 0), ('1_192.168.0.111', '3_CVE_1', 0), ]

vuln_to_device = [('1_CVE_1', '1_192.168.0.100', 5), ('2_CVE_1', '1_192.168.0.119', 5),
                  ('1_CVE_2', '1_10.23.0.1', 7), ('1_CVE_3', '1_10.23.0.5', 8),
                  ('1_CVE_4', '2_192.168.0.100', 9), ('3_CVE_1', '1_192.168.0.102', 5),
                  ('2_CVE_4', '1_192.168.0.111', 9),
                  ('1_CVE_5', '1_223.0.5.98', 8)]


def calculate_graph_threat(graph: nx.DiGraph, nodes: list) -> float:
    """
    Calculates graph threat from current nodes (don't need to consider vuln nodes)
    :param graph: our graph
    :param nodes: devices nodes
    :return:
    """
    calc = ThreatCalculator(graph)
    return calc.calculate_graph_threat(nodes)

def calculate_node_threat(graph: MultiDiGraph, node) -> float:
    """

    :param graph:
    :param node:
    :return:
    """
    calc = ThreatCalculator(graph)
    return calc.calculate_threat_for_node(node)


def find_best_countermeasure(graph, device_nodes_list, vuln_nodes_list):
    calc = ThreatCalculator(graph)
    choice, threat = calc.find_best_countermeasure_choice(device_nodes_list, vuln_nodes_list)
    return choice, threat


def print_graph(graph: MultiDiGraph, devices, vulns):
    pos = nx.spring_layout(graph)
    nx.draw_networkx_nodes(graph, pos,
                           nodelist=devices,
                           node_color='g',
                           node_size=80,
                           alpha=0.8)
    edge_weights = nx.get_edge_attributes(graph, 'cve')
    nx.draw_networkx_labels(graph, pos, font_size=9)
    # nx.draw_networkx_edge_labels(graph, pos, edge_labels=edge_weights, font_size=9)
    nx.draw_networkx_edges(graph, pos)
    write_dot(graph, 'multi.dot')
    return


def test():
    for node in device_nodes_list:
        graph.add_node(node)
    for node in vuln_nodes_list:
        graph.add_node(node)

    edges = device_to_vulns + vuln_to_device
    nodes = device_nodes_list + vuln_nodes_list

    graph.add_weighted_edges_from(edges)
    pos = nx.spring_layout(graph)
    nx.draw_networkx_nodes(graph, pos,
                           nodelist=device_nodes_list,
                           node_color='g',
                           node_size=80,
                           alpha=0.8)
    nx.draw_networkx_nodes(graph, pos,
                           nodelist=vuln_nodes_list,
                           node_color='r',
                           node_size=80,
                           alpha=0.8)
    edge_weights = nx.get_edge_attributes(graph, 'weight')
    nx.draw_networkx_labels(graph, pos, font_size=8)
    # nx.draw_networkx_labels(G, pos, device_nodes_list + vuln_nodes_list)
    nx.draw_networkx_edge_labels(graph, pos, edge_labels=edge_weights, font_size=8)
    nx.draw_networkx_edges(graph, pos)

    start_time = time()
    # cycles = nx.simple_cycles(graph)
    cycles = nx.find_cycle(graph, source='start')
    finish_time = time()
    cycle_list = list(cycles)

    start_time = time()
    components = get_strongly_connected_components(graph)
    #components_outs_map = map_components_to_out_edges(graph, components)
    #component_threat = subgraph_threat(graph, components[1])
    finish_time = time()

    graph_threat = calculate_graph_threat(graph, device_nodes_list)

    start_time = time()
    best_countermeasure, new_graph_threat = find_best_countermeasure(graph, device_nodes_list, vuln_nodes_list)
    finish_time = time()
    print(f"Graph threat = {graph_threat}")
    print(f"Best countermeasure = {best_countermeasure}")
    print(f"After deletion threat = {new_graph_threat}")
    print(f"Calculation time: {finish_time - start_time} s")


def generate_graph_and_test():
    strong_components_criticality = []
    strong_components_threatness = []
    n_tree_criticality = []
    graph, devices, vulns = generate_graph(5, 2, 3, chance=75)
    # print_graph(graph, devices, vulns)
    # strongly connected components
    strong_components = get_strongly_connected_components(graph)
    for component in strong_components:
        # we can count criticality from any node
        component_criticality = subgraph_criticality(graph, component, list(component)[0])

        # we can take only 1 node from strong connected component and multiply it on component size
        component_threatness = len(component) * calculate_node_threat(graph,list(component)[0])
        strong_components_criticality.append(component_criticality)
        strong_components_threatness.append(component_threatness)

        print(f"{component} criticality is {component_criticality}")
        print(f"{component} threatness is {component_threatness}")


    # graph threat
    graph_threat = calculate_graph_threat(graph, devices)

    start_time = time()
    # countermeasures and new threat
    best_countermeasure, new_graph_threat = find_best_countermeasure(graph, devices, vulns)
    countermeasure_search_time = time() - start_time
    visualizer = GraphVisualizer('AGG_new')
    start_time = time()
    # visualizer.read_graph(graph)
    time_spent_for_building = time() - start_time
    print(f"Spent {time_spent_for_building} seconds to build the graph")
    print(f"Graph threat = {graph_threat}")
    print(f"Best countermeasure = {best_countermeasure}")
    print(f"After deletion threat = {new_graph_threat}")
    print(f"Calculation time: {countermeasure_search_time} seconds")
    print(f"Finished")


def draw_graph_test():
    for node in device_nodes_list:
        graph.add_node(node)
    for node in vuln_nodes_list:
        graph.add_node(node)

    edges = device_to_vulns + vuln_to_device

    graph.add_weighted_edges_from(edges)
    visualizer = GraphVisualizer('auto_builded_graph')
    start_time = time()
    visualizer.read_graph(graph)
    time_spent_for_building = time() - start_time
    print(f"Spent {time_spent_for_building} seconds to build the graph")
    # visualizer.delete_graph()


def test_optimized_class():
    graph, devices, vulns = generate_graph(5, 2, 3, chance=75)

    vulns_amount = 0
    for vuln_list in vulns.values():
        vulns_amount += len(vuln_list)

    print(f"Vulnerabilities amount: {vulns_amount}")
    print(f"Nodes amount: {len(devices)}")
    # print_graph(graph, devices, vulns)
    graphOptimizer = GraphOptimizer(graph)
    start = time()
    graphOptimizer.optimize()
    graphOptimizer.compute_threat()
    spent_time = time() - start

    start = time()
    graphOptimizer.find_countermeasure()
    spent_time4 = time() - start

    start = time()
    graphOptimizer.intelligence_find_countermeasure()
    spent_time5 = time() - start

    start = time()
    calculate_graph_threat(graph, devices)
    spent_time2 = time() - start


    start = time()
    # find_best_countermeasure(graph, devices, vulns)
    spent_time3 = time() - start

    print(f"Intelligence countermeasure search time {spent_time5}")
    print(f"Basic countermeasure search time {spent_time4}")
    print(f"Simple countermeasure search time {spent_time2}")

def branching_rest():
    graph, devices, vulns = generate_graph(5, 2, 3, chance=75)
    branching = maximum_branching(graph)
    arborescence = maximum_spanning_arborescence(graph)

    pass

if __name__ == '__main__':
    # draw_graph_test()
    # generate_graph_and_test()
    test_optimized_class()
    # branching_rest()

