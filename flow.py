from graphviz import Digraph

def create_project_flowchart():
    # Create a new directed graph
    dot = Digraph(comment='IoT Fog Computing System Architecture')
    dot.attr(rankdir='TB')  # Top to Bottom direction
    
    # Define node styles
    dot.attr('node', shape='box', style='rounded')
    
    # Create clusters for different layers
    with dot.subgraph(name='cluster_0') as edge:
        edge.attr(label='Edge Layer')
        edge.attr('node', color='lightblue', style='filled,rounded')
        edge.node('edge_device1', 'Edge Device 1')
        edge.node('edge_device2', 'Edge Device 2')
        edge.node('edge_deviceN', 'Edge Device N')
    
    with dot.subgraph(name='cluster_1') as fog:
        fog.attr(label='Fog Layer')
        fog.attr('node', color='lightgreen', style='filled,rounded')
        fog.node('fog_server', 'Fog Server')
        fog.node('key_manager', 'Key Manager')
        fog.node('device_registry', 'Device Registry')
        fog.node('data_processor', 'Data Processor')
    
    with dot.subgraph(name='cluster_2') as cloud:
        cloud.attr(label='Cloud Layer')
        cloud.attr('node', color='lightpink', style='filled,rounded')
        cloud.node('lambda', 'AWS Lambda')
        cloud.node('dynamodb', 'DynamoDB')
        cloud.node('api_gateway', 'API Gateway')
    
    # Add edges for data flow
    # Edge to Fog connections
    dot.edge('edge_device1', 'fog_server', 'Encrypted Data')
    dot.edge('edge_device2', 'fog_server', 'Encrypted Data')
    dot.edge('edge_deviceN', 'fog_server', 'Encrypted Data')
    
    # Fog internal connections
    dot.edge('fog_server', 'key_manager', 'Key Rotation')
    dot.edge('fog_server', 'device_registry', 'Device Management')
    dot.edge('fog_server', 'data_processor', 'Process Data')
    
    # Fog to Cloud connections
    dot.edge('data_processor', 'api_gateway', 'Forward Alerts')
    dot.edge('api_gateway', 'lambda', 'Process Data')
    dot.edge('lambda', 'dynamodb', 'Store Data')
    
    # Return paths
    dot.edge('fog_server', 'edge_device1', 'Alert Broadcast', color='red')
    dot.edge('fog_server', 'edge_device2', 'Alert Broadcast', color='red')
    dot.edge('fog_server', 'edge_deviceN', 'Alert Broadcast', color='red')
    
    # Generate the flowchart
    dot.render('iot_fog_architecture', format='png', cleanup=True)
    print("Flowchart generated as 'iot_fog_architecture.png'")

if __name__ == "__main__":
    create_project_flowchart()