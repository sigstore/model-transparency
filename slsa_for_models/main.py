# Copyright Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing perepo_managerissions and
# limitations under the License.

import argparse

import tensorflow_cifar10 as tf
import pytorch_cifar10 as pt


def readOptions():
    parser = argparse.ArgumentParser('Train CIFAR10 models with TF/PT')
    model_formats = list(tf.supported_models().keys())
    model_formats += list(pt.supported_models().keys())
    parser.add_argument('model', choices=model_formats,
                        help='Model to generate (name implies framework)')
    return parser.parse_args()


def main(args):
    model_formats = list(tf.supported_models().keys())
    for model_format in model_formats:
        if args.model == model_format:
            return tf.model_pipeline(args.model)

    model_formats = list(pt.supported_models().keys())
    for model_format in model_formats:
        if args.model == model_format:
            return pt.model_pipeline(args.model)

    # we should not reach this case in the normal flow, but cover all corners
    raise ValueError("Model format not supported")


if __name__ == '__main__':
    args = readOptions()
    main(args)
