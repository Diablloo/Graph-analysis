import requests
import json

class GraphCreationError(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class GraphVisualizer:
    def __init__(self, graph_name):
        self.name = graph_name
        self.graph_id = None
        self.auth_token = ("BEARER eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NzcyOTk5ODgsImlhdCI6MTU3NDcwNzk4OCw"
                           "iaWQiOjUsInN1YiI6Im9ybHlfdGVzdGVyIn0.MI8itHOSF81GOKwjMgfXTSCztlceTd6reJHO33VeqP8")
    def create_graph(self):
        r = requests.post('https://3vis.neobit.ru/api/projects', json={"name": self.name},
                          headers={"Authorization":self.auth_token})


        if r.status_code != 200:
            raise GraphCreationError("Graph was not created")

        try:
            response = json.loads(r.text)
        except Exception as ex:
            raise GraphCreationError(f"Graph creation response error: {ex}")

        self.graph_id = response['msg']['project']['id']

    def delete_graph(self):
        r = requests.delete(f'https://3vis.neobit.ru/api/projects/{self.graph_id}', json={"pid": self.graph_id},
                          headers={"Authorization":self.auth_token})


        if r.status_code != 200:
            raise GraphCreationError("Graph was not deleted")

    def add_node(self, node_name, node_type):
        node_params = {
                        "node":
                           {
                               "x":1,"y":1,"name":node_name,"type":node_type
                           },
                       "pid": self.graph_id,
                       "needCompare":True
        }
        r = requests.post("https://3vis.neobit.ru/api/graph/node", json=node_params,
                          headers={"Authorization":self.auth_token})

        if r.status_code != 200:
            raise GraphCreationError("Node '{node_name}' type '{node_type}' was not created")

    def add_edge(self, node_first, node_second):
        pass
if __name__ == '__main__':
    vizual = GraphVisualizer("test_graph")
    vizual.create_graph()
    vizual.add_node('test_node','ip')
    vizual.delete_graph()
