import mongoose, { isValidObjectId } from "mongoose";
import { Like } from "../models/like.model.js";
import ApiError from "../utils/ApiError.js";
import ApiResponse from "../utils/ApiResponse.js";
import asyncHandler from "../utils/asyncHandler.js";
import { Product } from "../models/product.model.js";
import { Cart } from "../models/cart.model.js";
import { User } from "../models/user.model.js";

const AddToCart = asyncHandler(async (req, res) => {
  const { productId } = req.params;

  if (!productId) throw new ApiError(400, "Product Id not found");

  const product = await Product.findOne({ productId });

  if (!product) throw new ApiError(404, "Product Not found");

  const newCartItem = await Cart.create({
    user: req.user._id,
    cartProduct: product._id,
  });

  const createdCart = await Cart.findById(newCartItem._id);

  if (!createdCart)
    throw new ApiError(
      500,
      "Failed in adding item into cart due to internal error ! Please try again"
    );

  // Adding cart item to user's Cart section
  const user = await User.findById(req.user._id);
  user.cart.push(product._id);
  await user.save();

  res.status(200).json(new ApiResponse(200, createdCart, "Added successfully"));
});

const DeleteFromCart = asyncHandler(async (req, res) => {
  const { productId } = req.params;

  if (!productId) throw new ApiError(400, "Product Id not found");

  const product = await Product.findOne({ productId });

  if (!product)
    throw new ApiError(404, "Product Not found");

  const deletedItem = await Cart.findOneAndDelete({
    cartProduct: product._id,
  });

  if (!deletedItem)
    throw new ApiError(
      500,
      "Failed in deleting item from cart due to internal error ! Please try again"
    );

  // Adding cart item to user's Cart section
  const user = await User.findById(req.user._id);
  const index = user.cart.findIndex(item => item._id.equals(deletedItem._id));
  user.cart.splice(index);
  await user.save();

  res.status(200).json(new ApiResponse(200, deletedItem, "Added successfully"));
});

const GetCart = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id).populate("cart");

  if (!user)
    throw new ApiError(
      500,
      "failed to find due to internal error! Please try again"
    );

  res.status(200).json(new ApiResponse(200, user.cart, "Got the cart"));
});

const AddToWishlist = asyncHandler(async (req, res) => {
  const { productId } = req.params;

  if (!productId) throw new ApiError(400, "Product Id not found");

  const product = await Product.findOne({ productId });

  if (!product) throw new ApiError(404, "Product Not found");

  const newLikedProduct = await Like.create({
    user: req.user._id,
    likedProduct: product._id,
  });

  const createdLikedCard = await Like.findById(newLikedProduct._id);

  if (!createdLikedCard)
    throw new ApiError(
      500,
      "Failed in adding item into like due to internal error ! Please try again"
    );

  // Adding cart item to user's Cart section
  const user = await User.findById(req.user._id);
  user.likedProduct.push(product._id);
  await user.save();

  res
    .status(200)
    .json(new ApiResponse(200, createdLikedCard, "Added successfully"));
});

const DeleteFromWishlist = asyncHandler(async (req, res) => {
  const { productId } = req.params;

  if (!productId) throw new ApiError(400, "Product Id not found");

  const product = await Product.findOne({ productId });

  if (!product) throw new ApiError(404, "Product Not found");

  const deletedItem = await Like.findOneAndDelete({
    likedProduct: product._id,
  });

  if (!deletedItem)
    throw new ApiError(
      500,
      "Failed in deleting item from like due to internal error ! Please try again"
    );

  // deleting liked item from user's likedProduct section
  const user = await User.findById(req.user._id);
  const index = user.likedProduct.findIndex(item => item._id.equals(deletedItem._id));
  user.likedProduct.splice(index);
  await user.save();

  res.status(200).json(new ApiResponse(200, deletedItem, "Deleted successfully"));
});

const GetWishlist = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id).populate("likedProduct");

  if (!user)
    throw new ApiError(
      500,
      "failed to find due to internal error! Please try again"
    );

  res.status(200).json(new ApiResponse(200, user.likedProduct, "Got the cart"));
});

export {
  GetCart,
  AddToCart,
  GetWishlist,
  AddToWishlist,
  DeleteFromCart,
  DeleteFromWishlist,
};
