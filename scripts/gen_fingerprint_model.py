"""Generate a minimal ONNX fingerprint model: input [1,1,128,128] → output [1,64]."""
import onnx
from onnx import helper, TensorProto
import numpy as np

np.random.seed(42)

IN_C, IN_H, IN_W = 1, 128, 128
OUT_DIM = 64

# Flatten 1*128*128 = 16384
flat_dim = IN_C * IN_H * IN_W

# Weight matrix [flat_dim, OUT_DIM], bias [OUT_DIM]
weight = np.random.randn(flat_dim, OUT_DIM).astype(np.float32) * 0.01
bias = np.zeros(OUT_DIM, dtype=np.float32)

# Graph inputs
input_tensor = helper.make_tensor_value_info("input", TensorProto.FLOAT, [1, IN_C, IN_H, IN_W])
output_tensor = helper.make_tensor_value_info("output", TensorProto.FLOAT, [1, OUT_DIM])

# Initializers
weight_init = helper.make_tensor("weight", TensorProto.FLOAT, [flat_dim, OUT_DIM], weight.flatten().tolist())
bias_init = helper.make_tensor("bias", TensorProto.FLOAT, [OUT_DIM], bias.flatten().tolist())

# Shape for reshape: [1, -1]
shape_init = helper.make_tensor("shape", TensorProto.INT64, [2], [1, flat_dim])

# Nodes: Flatten → Gemm (matmul with transposed weight: input @ W + bias)
flatten_node = helper.make_node(
    "Reshape",
    inputs=["input", "shape"],
    outputs=["flattened"],
    name="flatten"
)

gemm_node = helper.make_node(
    "Gemm",
    inputs=["flattened", "weight", "bias"],
    outputs=["output"],
    name="gemm",
    alpha=1.0,
    beta=1.0,
    transB=1,  # Transpose weight to compute flattened @ weight^T + bias
)

graph = helper.make_graph(
    nodes=[flatten_node, gemm_node],
    name="fingerprint",
    inputs=[input_tensor],
    outputs=[output_tensor],
    initializer=[weight_init, bias_init, shape_init],
)

opset = helper.make_operatorsetid("", 18)
model = helper.make_model(graph, opset_imports=[opset], ir_version=8)

# Validate
onnx.checker.check_model(model)

out_path = "models/fingerprint_mini.onnx"
onnx.save(model, out_path)
print(f"Saved {out_path}")
print(f"Input:  {[d.dim_value for d in model.graph.input[0].type.tensor_type.shape.dim]}")
print(f"Output: {[d.dim_value for d in model.graph.output[0].type.tensor_type.shape.dim]}")
