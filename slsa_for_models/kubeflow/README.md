# Kubeflow Pipeline to generate ML model with attestations

## Prerequisutes
- A kubernetes cluster has been set up and running.
- Tekton Pipelines and Chains have been installed and running on the cluster.
- If pushing to private storage/repository
  - Workflow Identity federation has been setup with the `default` KSA.
- kubectl has been installed on your system.

## Build the images
For `clone`, `build-model` and `upload-model` `Tasks`, we need to build the images.
The Dockerfiles and supporting scripts for each Task are available under `slsa_for_models/kubeflow/images/`.

### Build clone image

```bash
cd slsa_for_models/kubeflow/images/clone
IMAGE=<path to your registry>/git-clone # e.g. docker.io/chitrangpatel/git-clone
docker buildx build -f Dockerfile -t ${IMAGE} .
docker push ${IMAGE}
```

### Build build-model image

```bash
cd slsa_for_models/kubeflow/images/build-model
IMAGE=<path to your registry>/build-model # e.g. docker.io/chitrangpatel/build-model
docker buildx build -f Dockerfile -t ${IMAGE} .
docker push ${IMAGE}
```

### Build upload-model image

```bash
cd slsa_for_models/kubeflow/images/upload-model
IMAGE=<path to your registry>/upload-model # e.g. docker.io/chitrangpatel/upload-model
docker buildx build -f Dockerfile -t ${IMAGE} .
docker push ${IMAGE}
```

## Install kubeflow
For exact details see https://github.com/kubeflow/kfp-tekton/tree/master/sdk#installation.
Requires `> python3.5`

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install kfp-tekton
```

## Compile the DSL to a yaml

The python DSL is shown in `model_transparency.py` file. Depending on the image you produced and tagged, you will have to update the `image` value in corresponding the `components`.
To generate a yaml from it, run:

```bash
python3 model_transparency.py
```

This will update the `model_transparency.yaml` file.

## Run the pipeline

```bash
kubectl apply -f model_transparency.yaml
```
