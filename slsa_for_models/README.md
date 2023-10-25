# SLSA for Models

To protect the supply chain of traditional software against tampering (like in
the [Solarwinds attack][solarwinds]), we can generate [SLSA][slsa] provenance,
for example by using the [SLSA L3 GitHub generator][slsa-generator].

This projects shows how we can use the same generator for training models via
GitHub Actions. While most of the ML models are too expensive to train in such a
fashion, this is a proof of concept to prove that _the same traditional software
supply chain protections can be applied to ML_. Future work will involve
covering training ML models that require access to accelerators (i.e., GPUs,
TPUs) or that require multiple hours for training. As an example, we could use
[Tekton Chains][tekton-chains] to support [training ML models using
Kubeflow][tekton-kubeflow].

When users download a given version of a model they can also check its
provenance by using [the SLSA verifier][slsa-verifier] repository. This can be
done automatically: for example the model serving pipeline could validate
provenance for all new models before serving them. The verification can also be
done manually, on demand.

As an additional benefit, having provenance for a model allows users to react
to vulnerabilities in a training framework: they can quickly determine if a
model needs to be retrained because it was created using a vulnerable version.

## Usage

TODO: Display how to run the action in the repo, show an example with images on
how to trigger workflow, show how to run the verifier manually

## Benchmarking

TODO: Table discussing performance of generating provenance for models, in
various formats, based on the running the GitHub acctions

[slsa-generator]: https://github.com/slsa-framework/slsa-github-generator
[slsa-verifier]: https://github.com/slsa-framework/slsa-verifier/
[slsa]: https://slsa.dev
[solarwinds]: https://www.techtarget.com/whatis/feature/SolarWinds-hack-explained-Everything-you-need-to-know
[tekton-chains]: https://github.com/tektoncd/chains
[tekton-kubeflow]: https://www.kubeflow.org/docs/components/pipelines/v1/sdk/pipelines-with-tekton/
