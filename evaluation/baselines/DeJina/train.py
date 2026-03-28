import os
os.environ["CUDA_VISIBLE_DEVICES"] = "1,2"
from data_handler import load_hf_dataset_with_token_res, load_hf_test_dataset_ordered_by_idx
from transformers import AutoTokenizer, AutoModel
import torch
import numpy as np
from tqdm import tqdm
import pytorch_warmup as warmup
from torch.cuda.amp import GradScaler, autocast
import pickle

import logging
import torch
from torch.utils.data import DataLoader, TensorDataset
import torch.nn.functional as F
import wandb

def mean_pooling(model_output, attention_mask):
    token_embeddings = model_output[0]
    input_mask_expanded = attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()
    return torch.sum(token_embeddings * input_mask_expanded, 1) / torch.clamp(input_mask_expanded.sum(1), min=1e-9)


logging.basicConfig(
    format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO
)
log = logging.getLogger('jina')

def evaluate(model, eval_loader):
    all_sims = []
    all_scores = []
    for batch in tqdm(eval_loader):
        model.eval()
        with torch.no_grad():
            input_ids1, attention_mask1, input_ids2, attention_mask2, scores = batch
            input_ids1 = input_ids1.cuda()
            attention_mask1 = attention_mask1.cuda()
            # input_ids1, attention_mask1 = input_ids1.cuda(), attention_mask1.cuda()
            # input_ids2, attention_mask2 = input_ids2.cuda(), attention_mask2.cuda()

            # Process the first set of sentences
            output1 = model(input_ids=input_ids1, attention_mask=attention_mask1)
            embeddings1 = mean_pooling(output1, attention_mask1)
            embeddings1 = F.normalize(embeddings1, p=2, dim=1)

            # Process the second set of sentences
            input_ids2 = input_ids2.cuda()
            attention_mask2 = attention_mask2.cuda()
            output2 = model(input_ids=input_ids2, attention_mask=attention_mask2)
            embeddings2 = mean_pooling(output2, attention_mask2)
            embeddings2 = F.normalize(embeddings2, p=2, dim=1)

            # Calculate similarity scores
            sims = torch.cosine_similarity(embeddings1, embeddings2)
            all_sims.extend(sims.detach().cpu().numpy())
            all_scores.extend(scores.detach().cpu().numpy())
        torch.cuda.empty_cache()
    eval_loss = np.mean((np.array(all_sims) - np.array(all_scores)) ** 2)
    return eval_loss

class CoentLoss(torch.nn.Module):
    def __init__(self, scale=20.0):
        super(CoentLoss, self).__init__()
        self.scale = scale

    def forward(self, scores, labels):
        scores = scores * self.scale
        scores = scores[:, None] - scores[None, :]
        labels = labels[:, None] < labels[None, :]
        labels = labels.float()
        scores = scores - (1 - labels) * 1e12
        scores = torch.cat((torch.zeros(1).cuda(), scores.view(-1)), dim=0)
        loss = torch.logsumexp(scores, dim=0)
        return loss

def train():
    jina_path = './checkpoints/full_1e'
    # jina_base_path = './checkpoints/jina-embeddings-v2-base-code'
    # tokenizer = AutoTokenizer.from_pretrained(jina_base_path)
    # tokenizer.save_pretrained('./checkpoints/full_1e')
    model = AutoModel.from_pretrained(jina_path, trust_remote_code=True).cuda()
    model = torch.nn.DataParallel(model).cuda()
    model.max_seq_length = 1024

    # max support 8192, but 3072 is max for 32G*2 GPU (batch_size 1)
    batch_size = 16
    eval_batch_size=64
    num_epochs = 1
    lr = 1e-5
    train_size = None
    eval_size = 30000
    warmup_steps = 2000
    logging_step = 1000
    eval_steps = 50000

    train_ds = './datasets_new/train_ds'
    eval_ds = './datasets_no_decl/eval_ds'


    log.info('Loading evaluation datasets...')
    eval_input_ids1, eval_attention_mask1, eval_input_ids2, eval_attention_mask2, score, eval_size = load_hf_dataset_with_token_res(eval_ds, size=eval_size)
    # eval_dataset = TensorDataset(eval_input_ids1, eval_attention_mask_1, eval_input_ids2, eval_attention_mask2, score)
    eval_dataset = TensorDataset(
        torch.Tensor(np.array(eval_input_ids1)).long(), torch.Tensor(np.array(eval_attention_mask1)).int(),
        torch.Tensor(np.array(eval_input_ids2)).long(), torch.Tensor(np.array(eval_attention_mask2)).int(),
        torch.Tensor(score)
    )
    eval_loader = DataLoader(eval_dataset, batch_size=eval_batch_size, shuffle=False)

    log.info('Loading training datasets...')
    train_input_ids1, train_attention_mask1, train_input_ids2, train_attention_mask2, score, train_size = load_hf_dataset_with_token_res(train_ds, size=train_size)
    # train_dataset = TensorDataset(train_input_ids1, train_attention_mask_1, train_input_ids2, train_attention_mask2, score)
    train_dataset = TensorDataset(
        torch.Tensor(np.array(train_input_ids1)).long(), torch.Tensor(np.array(train_attention_mask1)).int(),
        torch.Tensor(np.array(train_input_ids2)).long(), torch.Tensor(np.array(train_attention_mask2)).int(),
        torch.Tensor(score)
    )
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

    loss_fn = CoentLoss()
    num_steps = len(train_loader) * num_epochs
    save_steps = int(num_steps / 16)

    optimizer = torch.optim.AdamW(model.parameters(), lr=lr)
    lr_scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=num_steps)
    warmup_scheduler = warmup.LinearWarmup(optimizer, warmup_steps)
    scaler = GradScaler()

    wandb.init(project='jina-finetune-v2-full')
    for epoch in range(num_epochs):
        log.info(f'Epoch {epoch+1}/{num_epochs}')

        log.info('Training...')
        cur_step = 0
        total_loss = 0
        for batch in tqdm(train_loader):
            model.train()
            input_ids1, attention_mask1, input_ids2, attention_mask2, scores = batch
            input_ids = torch.cat((input_ids1, input_ids2), dim=0).cuda()
            attention_mask = torch.cat((attention_mask1, attention_mask2), dim=0).cuda()
            scores = scores.cuda()
            optimizer.zero_grad()
            with autocast():
                output = model(input_ids=input_ids, attention_mask=attention_mask)
                embeddings = mean_pooling(output, attention_mask)
                embeddings = F.normalize(embeddings, p=2, dim=1)
                embeddings1 = embeddings[:batch_size]
                embeddings2 = embeddings[batch_size:]
                if embeddings1.size(0) != batch_size or embeddings2.size(0) != batch_size:
                    continue
                sims = torch.cosine_similarity(embeddings1, embeddings2)
                loss = loss_fn(sims, scores)
            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()
            # loss.backward()
            # optimizer.step()
            with warmup_scheduler.dampening():
                lr_scheduler.step()
            total_loss += loss.detach().cpu().item()

            cur_step += 1
            wandb.log({'train_loss': total_loss})
            if cur_step % logging_step == 0:
                log.info(f'Step {cur_step}/{num_steps}, Loss: {total_loss/(logging_step)}')
                total_loss = 0
            if cur_step % eval_steps == 1:
                eval_loss = evaluate(model, eval_loader)
                log.info(f'Loss on evaluation set:{eval_loss}')
                wandb.log({'eval_loss': eval_loss})
            if cur_step % save_steps == 0:
                model.module.save_pretrained(f'./checkpoints/full_{epoch+1}_{cur_step}')
    model.module.save_pretrained('./checkpoints/full_5e')

def infer(model_path, ds_path, out_path, batch_size=256):
    model = AutoModel.from_pretrained(model_path, trust_remote_code=True).cuda()
    model = torch.nn.DataParallel(model).cuda()
    model.max_seq_length = 1024
    idx, input_ids, attention_mask = load_hf_test_dataset_ordered_by_idx(ds_path)
    test_dataset = TensorDataset(
        torch.Tensor(np.array(input_ids)).long(), torch.Tensor(np.array(attention_mask)).int()
    )
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

    res = []
    for batch in tqdm(test_loader):
        model.eval()
        with torch.no_grad():
            input_ids, attention_mask = batch
            input_ids = input_ids.cuda()
            attention_mask = attention_mask.cuda()
            output = model(input_ids=input_ids, attention_mask=attention_mask)
            embeddings = mean_pooling(output, attention_mask)
            embeddings = F.normalize(embeddings, p=2, dim=1)
            res.extend(embeddings.detach().cpu().numpy().tolist())
        torch.cuda.empty_cache()
    with open(out_path, 'wb') as file:
        pickle.dump(res, file)
    log.info(f'Results saved to {out_path}')

if __name__ == '__main__':
    train()