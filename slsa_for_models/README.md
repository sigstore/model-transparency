# SLSA for Models

To protect the supply chain of traditional software against tampering (like in
the [Solarwinds attack][solarwinds]), we can generate SLSA provenance, for
example by using the [SLSA L3 GitHub generator][slsa-generator].

This project shows how we can use the [SLSA L3 GitHub generator][slsa-generator]
to generate SLSA provenance for ML models. The SLSA generator was originally
developed for traditional software to protect against tampering with builds,
such as in the [Solarwinds attack][solarwinds], and this project is a proof of
concept that the _same supply chain protections can be applied to ML_.

Future work will involve covering training ML models that require access to
accelerators (i.e., GPUs, TPUs) or that require multiple hours for training. As
an example, we could use [Tekton Chains][tekton-chains] to support [training ML
models using Kubeflow][tekton-kubeflow].

When users download a given version of a model they can also check its
provenance by using [the SLSA verifier][slsa-verifier] repository. This can be
done automatically: for example the model serving pipeline could validate
provenance for all new models before serving them. The verification can also be
done manually, on demand.

As an additional benefit, having provenance for a model allows users to react
to vulnerabilities in a training framework: they can quickly determine if a
model needs to be retrained because it was created using a vulnerable version.

## Usage

We support both TensorFlow and PyTorch models. The example repo trains a model
on [CIFAR10][cifar10] dataset, saves it in one of the supported formats, and
generates provenance for the output. All of this happens during a [GitHub Actions
workflow][workflow] which takes as input the format to save the model into. The
supported formats are:

| Workflow Argument            | Training Framework | Model format                    |
|------------------------------|--------------------|---------------------------------|
| `tensorflow_model.keras`     | TensorFlow         | Keras format (default)          |
| `tensorflow_saved_model`     | TensorFlow         | SavedModel format               |
| `tensorflow_exported_model`  | TensorFlow         | Exported SavedModel format      |
| `tensorflow_hdf5_model.h5`   | TensorFlow         | Legacy HDF5 format              |
| `tensorflow_hdf5.weights.h5` | TensorFlow         | Legacy HDF5 weights only format |
| `pytorch_model.pth`          | PyTorch            | PyTorch default format          |
| `pytorch_full_model.pth`     | PyTorch            | PyTorch complete model format   |
| `pytorch_jitted_model.pt`    | PyTorch            | PyTorch TorchScript format      |

To test, fork this repository, then head over to the Actions tab and select the
"SLSA for ML models example" workflow. Since the workflow has a
`workflow_dispatch` trigger, it can be invoked on demand: click the `Run
workflow` button, then select the value for the "Name of the model" argument.

TODO: Screenshot of all the steps listed above.

After the worfklow finishes execution, there will be two archives in the
"Artifacts" section: one is the model that was trained and the other one is the
SLSA provenance attached to the model.

To verify the provenance, download both archives, unzip each and then run
`slsa-verifier`, making sure to replace the `--source-uri` argument with the
_path to your fork_. For example, for a PyTorch model:

```console
[...]$ slsa-verifier verify-artifact \
       --provenance-path pytorch_model.pth.intoto.jsonl \
       --source-uri github.com/google/model-transparency \
       pytorch_model.pth
Verified signature against tlog entry index 45172090 at URL: https://rekor.sigstore.dev/api/v1/log/entries/24296fb24b8ad77aba51e418ce36828f790c58a0f1304246a31eaadc35f36c2a0d03aabeb4b9ab07
Verified build using builder "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1.9.0" at commit 831b9521692f564156a61998b2478378e7dc6f49
Verifying artifact pytorch_model.pth: PASSED

PASSED: Verified SLSA provenance
```

TODO: link to a PyTorch model provenance from running GHA within the repo, fix
the output to match

**Note**: Because the SavedModel format is a directory, you will need to pass
multiple arguments to the verify command, to validate provenance for the entire
model. Passing a subset of the arguments will only partially check the
provenance of the model, covering only the files given as argument.

```console
[...]$ slsa-verifier verify-artifact \
       --provenance-path multiple.intoto.jsonl \
       --source-uri github.com/google/model-transparency \
       {fingerprint.pb,keras_metadata.pb,saved_model.pb,variables/*}
Verified signature against tlog entry index 45180918 at URL: https://rekor.sigstore.dev/api/v1/log/entries/24296fb24b8ad77a11ce42c9f7aa985a05c7d30467a77d14c9d96bddf7b9fa29657f72a86cde7b82
Verified build using builder "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1.9.0" at commit 831b9521692f564156a61998b2478378e7dc6f49
Verifying artifact fingerprint.pb: PASSED

Verified signature against tlog entry index 45180918 at URL: https://rekor.sigstore.dev/api/v1/log/entries/24296fb24b8ad77a11ce42c9f7aa985a05c7d30467a77d14c9d96bddf7b9fa29657f72a86cde7b82
Verified build using builder "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1.9.0" at commit 831b9521692f564156a61998b2478378e7dc6f49
Verifying artifact keras_metadata.pb: PASSED

Verified signature against tlog entry index 45180918 at URL: https://rekor.sigstore.dev/api/v1/log/entries/24296fb24b8ad77a11ce42c9f7aa985a05c7d30467a77d14c9d96bddf7b9fa29657f72a86cde7b82
Verified build using builder "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1.9.0" at commit 831b9521692f564156a61998b2478378e7dc6f49
Verifying artifact saved_model.pb: PASSED

Verified signature against tlog entry index 45180918 at URL: https://rekor.sigstore.dev/api/v1/log/entries/24296fb24b8ad77a11ce42c9f7aa985a05c7d30467a77d14c9d96bddf7b9fa29657f72a86cde7b82
Verified build using builder "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1.9.0" at commit 831b9521692f564156a61998b2478378e7dc6f49
Verifying artifact variables/variables.data-00000-of-00001: PASSED

Verified signature against tlog entry index 45180918 at URL: https://rekor.sigstore.dev/api/v1/log/entries/24296fb24b8ad77a11ce42c9f7aa985a05c7d30467a77d14c9d96bddf7b9fa29657f72a86cde7b82
Verified build using builder "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1.9.0" at commit 831b9521692f564156a61998b2478378e7dc6f49
Verifying artifact variables/variables.index: PASSED

PASSED: Verified SLSA provenance
```

TODO: link to a TF model from the repo, ensure output is correct

The verification of provenance can be done just before model gets loaded in the
serving pipeline.

[cifar10]: https://www.cs.toronto.edu/~kriz/cifar.html
[slsa-generator]: https://github.com/slsa-framework/slsa-github-generator
[slsa-verifier]: https://github.com/slsa-framework/slsa-verifier/
[slsa]: https://slsa.dev
[solarwinds]: https://www.techtarget.com/whatis/feature/SolarWinds-hack-explained-Everything-you-need-to-know
[tekton-chains]: https://github.com/tektoncd/chains
[tekton-kubeflow]: https://www.kubeflow.org/docs/components/pipelines/v1/sdk/pipelines-with-tekton/
[workflow]: https://github.com/google/model-transparency/blob/main/.github/workflows/slsa_for_ml.yml
