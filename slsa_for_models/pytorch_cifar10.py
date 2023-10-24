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


# We will do a lazy import for these 7 modules, exploiting Python's symbol
# resolution. The lazy import is needed to make sure we only import PyTorch
# libraries only if we want to train a PyTorch model.
torch = None
nn = None
F = None
optim = None
torchvision = None
transforms = None


def pretraining():
    """Perform setup required before training.

    Does the lazy loading of TensorFlow too, to prevent compatibility issues
    with mixing TensorFlow and PyTorch imports.
    """
    global torch
    global nn
    global F
    global optim
    global torchvision
    global transforms
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    import torch.optim as optim
    import torchvision
    import torchvision.transforms as transforms


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
    # Train a model based on tutorial from
    # https://pytorch.org/tutorials/beginner/blitz/cifar10_tutorial.html.
    # We inline the class to be able to use lazy loading of PyTorch modules.
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
                print(f'[{epoch}, {i:5d}], '
                      f'loss: {running_loss / batch_size :.3f}')
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


def supported_models():
    """Returns supported model types paired with method to save them."""
    return {
        'pytorch_model.pth': lambda m, p: torch.save(m.state_dict(), p),
        'pytorch_full_model.pth': lambda m, p: torch.save(m, p),
        'pytorch_jitted_model.pt': lambda m, p: torch.jit.script(m).save(p),
    }


def save_model(model, model_format):
    """Save the model after training to be transferred to production.

    Saves in the requested format, if supported by PyTorch.
    """
    saver = supported_models().get(model_format, None)
    if not saver:
        raise ValueError('Requested a model format not supported by PyTorch')
    saver(model, './' + model_format)


def model_pipeline(model_format):
    """Train a model and save it in the requested format."""
    pretraining()
    data = load_data()
    model = create_model()
    loss, optimizer = prepare_model(model)
    train_model(model, loss, optimizer, data[0])
    score_model(model, data[1])
    save_model(model, model_format)
