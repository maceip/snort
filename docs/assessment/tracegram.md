# Assessment: Tracegram (YuchenZhang-Academic/Tracegram)

The repository was cloned and read. Its trace classifier was re-run on the bundled IoT-Sentinel data, its shipped training logs were read, and simple baselines were run on the same data. This note records what works, what does not, and what it changes in `docs/plan.md`.

Environment: 4-core cloud container, CPU only, Python 3.12, torch 2.14 (CPU). `YuchenZhang-Academic/Tracegram@bbe3edf`.

## What it is

- **Pipeline:**
  - `dataset_pre_phase0_5`: pcap → per-packet token JSON.
  - `net3_flow_linear_cls_att`: per-flow encoder pretraining, a 24-layer linear-attention transformer language model over packet byte tokens (`model.py`).
  - `phase1_cls/classifier.py`: the trace classifier.
- **Classifier:** a bidirectional LSTM runs over the sequence of per-flow vectors, then attention with learned queries and a convolution plus MLP head. Flow importance is read from the attention weights.
- **Time gaps:** the shipped classifier models flow order through the LSTM but has no explicit inter-arrival or time-gap input.
- **Bundled data:** only IoT-Sentinel, already encoded into 256-d per-flow vectors by the pretrained flow encoder:
  - train 436 traces, valid 50, test 64;
  - 27 / 22 / 24 classes, under 3 test traces per class.
- **Labels:** stored as per-split indices and mapped to global device IDs through each split's `label2key` list.
- **Not bundled:** the encoders and pcaps needed to rebuild the other datasets.
- **Code quality:** research scripts with hard-coded relative paths, comments in Chinese, a `pytorch_warmup` copy vendored, and no tests.

## Runs

| Run | Result |
|---|---|
| `phase1_cls/classifier.py` on bundled IoT-Sentinel, 100 epochs, CPU | test macro-F1 1.000 (best validation 1.0), about 8 min |
| Shipped training logs, `phase1_cls/output/*/test.txt` (last column = test F1) | IoT-Sentinel with pretrained flow features 1.000; without them 0.931; with payload removed 0.876; without both 0.825; dataset `5p` 0.944; `etf` 1.000; `and` **0.395** |
| Bag-of-flows baselines on the same pre-encoded features (mean, or mean/std/max/min/count pooling, labels mapped through `label2key`) | logistic regression 1.000, random forest 1.000, 1-nearest-neighbour (cosine) 1.000 |

## Findings

1. **The perfect IoT-Sentinel score reproduces.** It is a 64-trace test set across 24 classes.
2. **The temporal aggregation is not what earns that score.** Mean-pooling the same pre-encoded flow vectors and using 1-nearest-neighbour also gets 1.000. On this data the signal is in the per-flow encoder, which is pretrained on packet bytes including payload, not in the order-aware aggregation.
3. **Without payload the shipped logs drop to 0.876**, and to 0.825 without the pretrained encoder. Our setting (flow logs such as Zeek, mostly encrypted traffic) is the no-payload case.
4. **There is an unreported weak result.** The shipped logs include a dataset (`and`) at test F1 0.395 that is not discussed among the paper's four datasets.
5. **The per-flow encoder cannot be checked from this repo.** The other paper datasets (UAV, KWS, ISD) and the encoder weights needed to reproduce them are not bundled.

## Verdict

- **What carries over:** the formulation (a trace is a bag of instances, scored with per-instance attention that doubles as evidence).
- **What doesn't:** the shipped results do not show the temporal aggregator adding value over pooled features, and the payload-dependent encoder does not fit flow-level telemetry.
- **Plan status:** stays a version 2 option.
- **Adoption test:** it must beat the pooled `[count, mean, std, min, max]` vector on our own traces under the plan's rule (§4.2), using flow and event features without payload, before it is adopted.

## Reproduce

```bash
cp -r Tracegram/phase1_cls run && cd run
# set train_path/valid_path/test_path to ../Tracegram/dataset_pre_phase1/dataset/captures_IoT-Sentinel_pre_{train,valid,test}.json
python classifier.py            # last line of output/<name>/test.txt: epoch, best valid F1, train F1, valid F1, test F1
# baseline: mean-pool each trace's flow vectors, map labels with int(label2key[raw]) per split, fit LogisticRegression / 1-NN
```
