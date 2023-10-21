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

import tensorflow as tf
import tensorflow_datasets as tfds


def pretraining():
  """Perform setup required before training."""
  tf.config.optimizer.set_jit(False)  # TODO


def load_data():
  """Load the CIFAR10 data.

  Obtains both the train and the test splits. According to
  https://www.cs.toronto.edu/~kriz/cifar.html, there should be 50000 training
  images and 10000 test ones. Each image is 32x32 RGB.

  Data is normalized to be in [0, 1). Labels are one-hot encoded.

  Returns train and test pairs. Each pair consists of features and labels
  vectors of similar size.
  """
  result = tfds.load('cifar10', batch_size = -1)
  x_train = result['train']['image']
  y_train = result['train']['label']
  x_test = result['test']['image']
  y_test = result['test']['label']

  # transform input
  x_train = x_train.numpy().astype('float32') / 256
  x_test = x_test.numpy().astype('float32') / 256
  y_train = tf.keras.utils.to_categorical(y_train, num_classes=10)
  y_test = tf.keras.utils.to_categorical(y_test, num_classes=10)

  return (x_train, y_train), (x_test, y_test)


def create_model(in_shape):
  """Create a TensorFlow NN model.

  The model is taken from the tutorial at
  https://www.tensorflow.org/xla/tutorials/autoclustering_xla.

  We need to pass as argument the expected input shape.

  Returns the model.
  """
  x, _, c = in_shape
  return tf.keras.models.Sequential([
      tf.keras.layers.Conv2D(x, (c, c), padding='same', input_shape=in_shape),
      tf.keras.layers.Activation('relu'),
      tf.keras.layers.Conv2D(x, (c, c)),
      tf.keras.layers.Activation('relu'),
      tf.keras.layers.MaxPooling2D(pool_size=(2,2)),
      tf.keras.layers.Dropout(0.25),
      tf.keras.layers.Conv2D(2*x, (c, c), padding='same'),
      tf.keras.layers.Activation('relu'),
      tf.keras.layers.Conv2D(2*x, (c, c)),
      tf.keras.layers.Activation('relu'),
      tf.keras.layers.MaxPooling2D(pool_size=(2,2)),
      tf.keras.layers.Dropout(0.25),
      tf.keras.layers.Flatten(),
      tf.keras.layers.Dense(512),
      tf.keras.layers.Activation('relu'),
      tf.keras.layers.Dropout(0.5),
      tf.keras.layers.Dense(10),
      tf.keras.layers.Activation('softmax'),
  ])


def prepare_model(model):
  """Prepare model for training with loss and optimizer."""
  opt = tf.keras.optimizers.RMSprop(learning_rate=0.0001)
  model.compile(loss='categorical_crossentropy',
                optimizer=opt,
                metrics=['accuracy'])
  return model


def train_model(model, train, test):
  """Train a model on the training set.

  The test set is used for cross validation.
  """
  x, y = train
  model.fit(x, y, batch_size=256, epochs=25,
            validation_data=test, shuffle=True, verbose=0)


def score_model(model, test):
  """Score a trained model on the test set."""
  x, y = test
  scores = model.evaluate(x, y, verbose=1)
  print(f'Test loss: {scores[0]}')
  print(f'Test accuracy: {scores[1]}')


def save_model(model):
  """Save the model after training to be transferred to production.

  Save in multiple formats supported by TensorFlow.
  """
  # New Keras format
  path = './model.keras'
  model.save(path, save_format='keras')
  # TF SavedModel formats, full model and weights only
  path = './model_tf'
  model.save(path, save_format='tf')
  path = './exported_model'
  model.export(path)
  # Legacy HDFS format, full model and weights only
  path = './model.h5'
  model.save(path, save_format='h5')
  path = './serialized.weights.h5'
  model.save_weights(path)


def main():
  pretraining()
  data = load_data()
  model = create_model(data[0][0].shape[1:])
  model = prepare_model(model)
  train_model(model, data[0], data[1])
  score_model(model, data[1])
  save_model(model)


if __name__ == '__main__':
  main()
