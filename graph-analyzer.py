from time import time

import networkx as nx
import matplotlib.pyplot as plt
# import pygraphviz
from utils.graph_utils import generate_graph, get_strongly_connected_components, map_components_to_out_edges, \
    subgraph_threat
from utils.threat_calc import ThreatCalculator

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
    # nodes = ['2_192.168.0.100']
    return calc.calculate_graph_threat(nodes)


def find_best_countermeasure(graph, device_nodes_list, vuln_nodes_list):
    calc = ThreatCalculator(graph)
    choice, threat = calc.find_best_countermeasure_choice(device_nodes_list, vuln_nodes_list)
    return choice, threat


def print_graph(graph, devices, vulns):
    pos = nx.spring_layout(graph)
    nx.draw_networkx_nodes(graph, pos,
                           nodelist=devices,
                           node_color='g',
                           node_size=80,
                           alpha=0.8)
    nx.draw_networkx_nodes(graph, pos,
                           nodelist=vulns,
                           node_color='r',
                           node_size=80,
                           alpha=0.8)
    edge_weights = nx.get_edge_attributes(graph, 'weight')
    nx.draw_networkx_labels(graph, pos, font_size=9)
    nx.draw_networkx_edge_labels(graph, pos, edge_labels=edge_weights, font_size=9)
    nx.draw_networkx_edges(graph, pos)
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
    components_outs_map = map_components_to_out_edges(graph, components)
    component_threat = subgraph_threat(graph, components[1])
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
    graph, devices, vulns = generate_graph(4, 2, 3, chance=80)
    print_graph(graph, devices, vulns)
    # strongly connected components
    components = get_strongly_connected_components(graph)

    # graph threat
    graph_threat = calculate_graph_threat(graph, devices)

    start_time = time()
    # countermeasures and new threat
    best_countermeasure, new_graph_threat = find_best_countermeasure(graph, devices, vulns)
    finish_time = time()
    print(f"Graph threat = {graph_threat}")
    print(f"Best countermeasure = {best_countermeasure}")
    print(f"After deletion threat = {new_graph_threat}")
    print(f"Calculation time: {finish_time - start_time} s")
    print(f"Finished")


if __name__ == '__main__':
    test()
