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

import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
import torchvision
import torchvision.transforms as transforms


# Cifar10 model from
# https://pytorch.org/tutorials/beginner/blitz/cifar10_tutorial.html
class MyModel(nn.Module):
  def __init__(self):
    super().__init__()
    self.conv1 = nn.Conv2d(3, 6, 5)
    self.pool = nn.MaxPool2d(2, 2)
    self.conv2 = nn.Conv2d(6, 16, 5)
    self.fc1 = nn.Linear(16 * 5 * 5, 120)
    self.fc2 = nn.Linear(120, 84)
    self.fc3 = nn.Linear(84, 10)


  def forward(self, x):
    x = self.pool(F.relu(self.conv1(x)))
    x = self.pool(F.relu(self.conv2(x)))
    x = torch.flatten(x, 1)
    x = F.relu(self.fc1(x))
    x = F.relu(self.fc2(x))
    x = self.fc3(x)
    return x


def pretraining():
  """Perform setup required before training."""
  pass  # Nothing needed here


def load_data():
  """Load the CIFAR10 data.

  Obtains both the train and the test splits. According to
  https://www.cs.toronto.edu/~kriz/cifar.html, there should be 50000 training
  images and 10000 test ones. Each image is 32x32 RGB.

  Data is normalized to be in range [-1, 1].

  Returns iterators to train and test sets.
  """
  transform = transforms.Compose([
      transforms.ToTensor(),
      transforms.Normalize((0.5, 0.5, 0.5), (0.5, 0.5, 0.5))
  ])

  batch_size = 4
  num_workers = 2

  trainset = torchvision.datasets.CIFAR10(root='./data', train=True,
                                          download=True, transform=transform)
  trainloader = torch.utils.data.DataLoader(trainset, batch_size=batch_size,
                                            shuffle=True,
                                            num_workers=num_workers)
  testset = torchvision.datasets.CIFAR10(root='./data', train=False,
                                          download=True, transform=transform)
  testloader = torch.utils.data.DataLoader(testset, batch_size=batch_size,
                                            shuffle=True,
                                            num_workers=num_workers)

  return trainloader, testloader


def create_model():
  """Create a Torch NN model.

  The model is taken from the tutorial at
  https://pytorch.org/tutorials/beginner/blitz/cifar10_tutorial.html.

  Returns the model.
  """
  return MyModel()


def prepare_model(model):
  """Prepare model for training with loss and optimizer."""
  # We only need to return loss and optimizer
  loss = nn.CrossEntropyLoss()
  optimizer = optim.SGD(model.parameters(), lr=0.001, momentum=0.9)
  return loss, optimizer


def train_model(model, loss, optimizer, train):
  """Train a model on the training set."""
  num_epochs = 2
  batch_size = 2000
  for epoch in range(num_epochs):
    running_loss = 0.0
    for i, data in enumerate(train, 1):
      x, y = data
      optimizer.zero_grad()
      outputs = model(x)
      loss_score = loss(outputs, y)
      loss_score.backward()
      optimizer.step()
      running_loss += loss_score.item()
      if i % batch_size == 0:
        print(f'[{epoch}, {i:5d}], loss: {running_loss / batch_size :.3f}')
        running_loss = 0.0


def score_model(model, test):
  """Score a trained model on the test set."""
  correct = 0
  total = 0
  with torch.no_grad():
    for data in test:
      x, y = data
      outputs = model(x)
      _, predicted = torch.max(outputs.data, 1)
      total += y.size(0)
      correct += (predicted == y).sum().item()
  print(f'Test accuracy: {correct / total}')


def save_model(model):
  """Save the model after training to be transferred to production.

  Save in multiple formats supported by PyTorch.
  """
  path = './model.pth'
  torch.save(model.state_dict(), path)
  path = './full_model.pth'
  torch.save(model, path)
  path = './jitted_model.pt'
  torch.jit.script(model).save(path)


def main():
  pretraining()
  data = load_data()
  model = create_model()
  loss, optimizer = prepare_model(model)
  train_model(model, loss, optimizer, data[0])
  score_model(model, data[1])
  save_model(model)


if __name__ == '__main__':
  main()
