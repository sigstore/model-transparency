import json

from kfp import components
from kfp import dsl
import kfp_tekton
from kubernetes.client.models import V1PersistentVolumeClaimSpec
from kubernetes.client.models import V1ResourceRequirements


def git_clone(url: str, target: str):
    return components.load_component_from_text(
        """
    name: git-clone
    description: Git clone
    inputs:
      - {name: url, type: String}
      - {name: target, type: Directory}
    outputs:
      - {name: CHAINS-GIT_COMMIT, type: String}
      - {name: CHAINS-GIT_URL, type: String}
    implementation:
      container:
        image: chitrangpatel/git-clone
        command:
          - ./clone.sh
        args:
          - -u
          - {inputValue: url}
          - -c
          - {outputPath: CHAINS-GIT_COMMIT}
          - -p
          - {outputPath: CHAINS-GIT_URL}
          - -t
          - {inputValue: target}
    """
    )(url=url, target=target)


def build_model(requirements: str, source: str, model: str, work_dir: str):
    return components.load_component_from_text(
        """
    name: build-model
    description: Build Model
    inputs:
      - {name: requirements, type: String}
      - {name: source, type: String}
      - {name: model, type: String}
      - {name: work, type: String}
    outputs:
      - {name: digest, type: String}
    implementation:
      container:
        image: chitrangpatel/build-model
        command:
          - ./build.sh
        args:
          - -r
          - {inputValue: requirements}
          - -w
          - {inputValue: work}
          - -s
          - {inputValue: source}
          - -m
          - {inputValue: model}
          - -d
          - {outputPath: digest}
    """
    )(requirements=requirements, source=source, model=model, work=work_dir)


def upload_model(location: str, source: str, work_dir: str):
    return components.load_component_from_text(
        """
    name: upload-model
    description: Upload Model
    inputs:
      - {name: location, type: String}
      - {name: source, type: String}
      - {name: work, type: String}
    outputs:
      - {name: model_ARTIFACT_URI, type: String}
      - {name: model_ARTIFACT_DIGEST, type: String}
    implementation:
      container:
        image: chitrangpatel/upload-model
        command:
          - ./upload.sh
        args:
          - -r
          - {outputPath: model_ARTIFACT_URI}
          - -w
          - {inputValue: work}
          - -c
          - {outputPath: model_ARTIFACT_DIGEST}
          - -s
          - {inputValue: source}
          - -l
          - {inputValue: location}
    """
    )(location=location, source=source, work=work_dir)


@dsl.pipeline(
    name="clone-build-push-pipeline",
    description="Clone the source code, build & upload the model to GCS.",
)
def clone_build_push(
    url: str = "https://github.com/sigstore/model-transparency",
    target: str = "source",
    model: str = "pytorch_model.pth",
):
    """A three-step pipeline with the first two steps running in parallel."""
    source_code = "$(workspaces.shared-ws.path)/source"
    relative_main_path = "slsa_for_models/main.py"
    relative_requirements = "slsa_for_models/install/requirements_Linux.txt"
    gcs_path = "gs://chitrang-ml-models/pytorch_model.pth"

    clone_task = git_clone(url, source_code)
    workspace_json = {"shared-ws": {}}
    clone_task.add_pod_annotation("workspaces", json.dumps(workspace_json))

    build_task = build_model(
        requirements=relative_requirements,
        work_dir=source_code,
        source=relative_main_path,
        model=model,
    )
    build_task.after(clone_task)
    build_task.add_pod_annotation("workspaces", json.dumps(workspace_json))

    upload_task = upload_model(gcs_path, model, source_code)
    upload_task.after(build_task)
    upload_task.add_pod_annotation("workspaces", json.dumps(workspace_json))


pipeline_conf = kfp_tekton.compiler.pipeline_utils.TektonPipelineConf()
pipeline_conf.add_pipeline_workspace(
    workspace_name="shared-ws",
    volume_claim_template_spec=V1PersistentVolumeClaimSpec(
        access_modes=["ReadWriteOnce"],
        resources=V1ResourceRequirements(requests={"storage": "5Gi"}),
    ),
)
pipeline_conf.set_generate_component_spec_annotations(False)

if __name__ == "__main__":
    from kfp_tekton.compiler import TektonCompiler

    TektonCompiler().compile(
        clone_build_push,
        __file__.replace(".py", ".yaml"),
        tekton_pipeline_conf=pipeline_conf,
    )
