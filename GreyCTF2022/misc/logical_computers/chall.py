import torch

def tensorize(s : str) -> torch.Tensor:
  return torch.Tensor([(1 if (ch >> i) & 1 == 1 else -1) for ch in list(map(ord, s)) for i in range(8)])

class NeuralNetwork(torch.nn.Module):
  def __init__(self, in_dimension, mid_dimension, out_dimension=1):
    super(NeuralNetwork, self).__init__()
    self.layer1 = torch.nn.Linear(in_dimension, mid_dimension)
    self.layer2 = torch.nn.Linear(mid_dimension, out_dimension)

  def step_activation(self, x : torch.Tensor) -> torch.Tensor:
    x[x <= 0] = -1
    x[x >  0] = 1
    return x

  def forward(self, x : torch.Tensor) -> int:
    x = self.layer1(x)
    x = self.step_activation(x)
    x = self.layer2(x)
    x = self.step_activation(x)
    return int(x)

#flag = input("Enter flag: ")
flag = 'A'*20
in_data = tensorize(flag)
in_dim	= len(in_data)

print(flag, in_data, in_dim)

model = NeuralNetwork(in_dim, 1280)
model.load_state_dict(torch.load("model.pth"))

l1w, l1b, l2w, l2b = model.state_dict().values()
l2w = l2w[0]
print(l2b)
assert l2b == -1279 # meaning: just make everything provide 1!
print(l2w) # l2w[i] means "should hidden node i be positive, or non-positive?"
print(all(v<0 for v in l1b)) # observation: all l1 biases are negative

# meme3 solver
from z3 import *
s = Solver()
inp = [Int("x%d" % i) for i in range(in_dim)]
for i in inp: # input bits are 1 or -1 (meaning 0)
  s.add(Or(i == 1, i == -1))
for i in range(1280): # for every hidden node
  nodes = [inp[j] for j,b in enumerate(l1w[i]) if b == 1] # take all relevant input nodes (NOTE: this works because l1 weights are all 0 or 1)
  bias = IntVal(int(l1b[i]))
  total = Sum(nodes)+bias # value passed to activation func
  if l2w[i] == 1: # this hidden node must be positive
    # OBSERVATION: Sum(nodes) is alwqys <= 1-bias
    # so if the hidden node must be +ve, then ALL of its incoming edges must provide +1
    for n in nodes:
      s.add(n == 1)
  else:
    s.add(total <= 0)
print(s.check())
m = s.model()

inp = [m[inp[i]] for i in range(in_dim)] # this is basically the correct input tensor, but a list
# lol idk how to convert tensor to string quickly
from pwn import group
flag = ''.join(chr(int(''.join(['1' if v == 1 else '0' for v in g][::-1]),2)) for g in group(8, inp))
print(flag)
in_data = tensorize(flag)

if model(in_data) == 1:
	print("Yay correct! That's the flag!")
else:
	print("Awww no...")
