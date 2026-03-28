import collections
from dataset import GraphEditDistanceDataset, FixedGraphEditDistanceDataset
from graphembeddingnetwork import GraphEmbeddingNet, GraphEncoder, GraphAggregator
from graphmatchingnetwork import GraphMatchingNet
import copy
import torch
import random
import os

GraphData = collections.namedtuple('GraphData', [
    'from_idx',
    'to_idx',
    'node_features',
    'edge_features',
    'graph_idx',
    'n_graphs'])


def reshape_and_split_tensor(tensor, n_splits):
    """Reshape and split a 2D tensor along the last dimension.

    Args:
      tensor: a [num_examples, feature_dim] tensor.  num_examples must be a
        multiple of `n_splits`.
      n_splits: int, number of splits to split the tensor into.

    Returns:
      splits: a list of `n_splits` tensors.  The first split is [tensor[0],
        tensor[n_splits], tensor[n_splits * 2], ...], the second split is
        [tensor[1], tensor[n_splits + 1], tensor[n_splits * 2 + 1], ...], etc..
    """
    feature_dim = tensor.shape[-1]
    tensor = torch.reshape(tensor, [-1, feature_dim * n_splits])
    tensor_split = []
    for i in range(n_splits):
        tensor_split.append(tensor[:, feature_dim * i: feature_dim * (i + 1)])
    return tensor_split

def save_model(model, optimizer, best, path='saved/checkpoint.pt'):
    dirname = os.path.dirname(path)
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    checkpoint = {
        'model': model.state_dict(),
        'optimizer': optimizer.state_dict(),
        'best': best,
    }
    torch.save(checkpoint, path)
  
def build_model(config, node_feature_dim, edge_feature_dim):
    """Create model for training and evaluation.

    Args:
      config: a dictionary of configs, like the one created by the
        `get_default_config` function.
      node_feature_dim: int, dimensionality of node features.
      edge_feature_dim: int, dimensionality of edge features.

    Returns:
      tensors: a (potentially nested) name => tensor dict.
      placeholders: a (potentially nested) name => tensor dict.
      AE_model: a GraphEmbeddingNet or GraphMatchingNet instance.

    Raises:
      ValueError: if the specified model or training settings are not supported.
    """
    config['encoder']['node_feature_dim'] = node_feature_dim
    config['encoder']['edge_feature_dim'] = edge_feature_dim

    encoder = GraphEncoder(**config['encoder'])
    aggregator = GraphAggregator(**config['aggregator'])
    if config['model_type'] == 'embedding':
        model = GraphEmbeddingNet(
            encoder, aggregator, **config['graph_embedding_net'])
    elif config['model_type'] == 'matching':
        model = GraphMatchingNet(
            encoder, aggregator, **config['graph_matching_net'])
    else:
        raise ValueError('Unknown model type: %s' % config['model_type'])
    
    cp_path = config['cp_path']
    if os.path.exists(cp_path):
        checkpoint = torch.load(cp_path)
        model.load_state_dict(checkpoint['model'])
    
    optimizer = torch.optim.Adam(model.parameters(),
                                 lr=config['training']['learning_rate'], weight_decay=1e-5)
    
    if os.path.exists(cp_path):
        optimizer.load_state_dict(checkpoint['optimizer'])
        for state in optimizer.state.values():  
            for k, v in state.items():  
                if isinstance(v, torch.Tensor):
                    use_cuda = torch.cuda.is_available()
                    device = torch.device('cuda:0' if use_cuda else 'cpu')
                    state[k] = v.to(device)
    
    return model, optimizer


def build_datasets(config):
    """Build the training and evaluation datasets."""
    config = copy.deepcopy(config)

    if config['data']['problem'] == 'graph_edit_distance':
        dataset_params = config['data']['dataset_params']
        validation_dataset_size = dataset_params['validation_dataset_size']
        train_dataset_path = dataset_params['train_dataset_path']
        valid_dataset_path = dataset_params['valid_dataset_path']
        del dataset_params['validation_dataset_size']
        del dataset_params['train_dataset_path']
        del dataset_params['valid_dataset_path']
        dataset_params['dataset_path'] = train_dataset_path
        training_set = GraphEditDistanceDataset(**dataset_params)
        dataset_params['dataset_size'] = validation_dataset_size
        dataset_params['dataset_path'] = valid_dataset_path
        validation_set = FixedGraphEditDistanceDataset(**dataset_params)
    else:
        raise ValueError('Unknown problem type: %s' % config['data']['problem'])
    return training_set, validation_set


def get_graph(batch):
    if len(batch) != 2:
        # if isinstance(batch, GraphData):
        graph = batch
        node_features = torch.from_numpy(graph.node_features)
        edge_features = torch.from_numpy(graph.edge_features)
        from_idx = torch.from_numpy(graph.from_idx).long()
        to_idx = torch.from_numpy(graph.to_idx).long()
        graph_idx = torch.from_numpy(graph.graph_idx).long()
        return node_features, edge_features, from_idx, to_idx, graph_idx
    else:
        graph, labels = batch
        node_features = torch.from_numpy(graph.node_features)
        edge_features = torch.from_numpy(graph.edge_features)
        from_idx = torch.from_numpy(graph.from_idx).long()
        to_idx = torch.from_numpy(graph.to_idx).long()
        graph_idx = torch.from_numpy(graph.graph_idx).long()
        labels = torch.from_numpy(labels).long()
    return node_features, edge_features, from_idx, to_idx, graph_idx, labels
