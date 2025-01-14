import asyncHandler from "../utils/asyncHandler.js";
import ApiError from "../utils/ApiError.js";
import ApiResponse from "../utils/ApiResponse.js";
import {
  UploadFileToCloudinary,
  DeleteFileFromCloudinary,
} from "../utils/Cloudinary.js";
import { Product } from "../models/product.model.js";

// This will upload a new product to the database
const UploadNewProduct = asyncHandler(async (req, res) => {
  const { productId, name, description, summery, oldPrice, newPrice, rating } =
    req.body;

  console.log(req.body);


  if ([name, description, summery].some((field) => field.trim() === ""))
    throw new ApiError(400, "All fields are required");

  if (!newPrice)
    throw new ApiError(400, "Product price is very important and compulsory");

  if (!rating)
    throw new ApiError(
      400,
      "Please provide rating of the product! It is compulsory"
    );

  if (!productId)
    throw new ApiError(400, "Product Id is very important and compulsory");

  const isUploaded = await Product.findOne({ productId });

  if (isUploaded) throw new ApiError(401, "This product is already uploaded");

  const imageLocalFilePath = req.file?.path;

  console.log(imageLocalFilePath);

  if (!imageLocalFilePath) throw new ApiError(401,"Product image is Compulsory.");

  const Image = await UploadFileToCloudinary(imageLocalFilePath);

  if (!Image)
    throw new ApiError(
      500,
      "Failed to Upload due to some internal error ! Please try again"
    );

  const newProduct = await Product.create({
    productId,
    name,
    description,
    summery,
    price: {
      wasPrice: oldPrice || null,
      currentPrice: newPrice,
    },
    rating,
    images: [Image.secure_url],
  });

  const createdProduct = await Product.findById(newProduct._id);

  if (!createdProduct)
    throw new ApiError(
      500,
      "Failed to upload product due to internal server error! please try again"
    );

  res
    .status(200)
    .json(
      new ApiResponse(200, createdProduct, "Product Uploaded successfully")
    );
});

// Returns product details of a certain product. It takes the productId
const GetProductDetails = asyncHandler(async (req, res) => {
  const { productId } = req.params;

  if (!productId)
    throw new ApiError(
      400,
      "product Id isn't found! Please provide product id."
    );

  const product = await Product.findOne({ productId });

  if (!product)
    throw new ApiError(
      400,
      "Product not found! may be due to invalid product Id. Please check and try again"
    );

  res.status(200).json(new ApiResponse(200, product, "Got your product"));
});

// Returns all the product uploaded to the database
const GetAllProducts = asyncHandler(async (req, res) => {

  const products = await Product.find();

  if (!products)
    throw new ApiError(
      400,
      "Product not found! may be due to invalid product Id. Please check and try again"
    );

  res.status(200).json(new ApiResponse(200, products, "Got your product"));
});

// This function will clear all the previously uploaded images and upload newer ones
const ClearAndUpdateImages = asyncHandler(async (req, res) => {
  const { productId } = req.params;

  // console.log(req);
  

  if (!productId)
    throw new ApiError(
      400,
      "product Id isn't found! Please provide product id."
    );

  const product = await Product.findOne({ productId });

  if (!product)
    throw new ApiError(
      400,
      "Product not found! may be due to invalid product Id. Please check and try again"
    );

  if (!req.files || req.files.length === 0)
    throw new ApiError(400, "New Images not found! Please upload the images");

  //---------- Deleting all previous images
  if (product.images.length !== 0) {
    const deletePromises = product.images.map((image) =>
      DeleteFileFromCloudinary(image)
    );
    await Promise.all(deletePromises);
    product.images = [];

    if (product.images.length > 0)
      throw new ApiError(
        500,
        "Failed to delete all images due to server error! Please try again."
      );
  }

  const uploadPromises = req.files.map(async (image) => {
    const UploadedImg = await UploadFileToCloudinary(image.path);
    console.log(image.originalname, " is uploaded");
    product.images.push(UploadedImg.url);
  });

  await Promise.all(uploadPromises);
  await product.save();

  res
    .status(200)
    .json(
      new ApiResponse(
        200,
        product,
        "All old images are deleted and new are uploaded "
      )
    );
});

// This is for adding Images to a certain product. The max limit of Images to a product is '5'.
// So This function will only accept max of 4 images.
const AddImages = asyncHandler(async (req, res) => {
  const MAX_IMAGES = 5;
  const { productId } = req.params;

  // Validate productId
  if (!productId) {
    throw new ApiError(
      400,
      "Product Id isn't found! Please provide product id."
    );
  }

  // Validate the product existence
  const product = await Product.findOne(productId);
  if (!product) {
    throw new ApiError(
      400,
      "Product not found! May be due to invalid product Id. Please check and try again."
    );
  }

  // Validate the images in request
  const images = req.files;
  if (!images || images.length === 0) {
    throw new ApiError(400, "New Images not found! Please upload the images.");
  }
  if (images.length > MAX_IMAGES - 1) {
    throw new ApiError(
      400,
      `You can upload a maximum of ${MAX_IMAGES} images.`
    );
  }

  // Ensure the total number of images does not exceed MAX_IMAGES
  if (product.images.length + images.length > MAX_IMAGES) {
    throw new ApiError(
      400,
      `Adding these images would exceed the maximum allowed ${MAX_IMAGES} images.`
    );
  }

  // Upload new images
  const uploadPromises = images.map(async (image) => {
    const uploadedImg = await UploadFileToCloudinary(image.path);
    console.log(`${image.originalname} is uploaded`);
    product.images.push(uploadedImg.url);
  });
  await Promise.all(uploadPromises);

  // Save the updated product
  await product.save();

  res
    .status(200)
    .json(new ApiResponse(200, product, "Images added successfully."));
});

// Updating Product details. This will take the productId via params and all other details in body
const UpdateProductDetails = asyncHandler(async (req, res) => {
  const { productId } = req.params;
  const { name, description, summery, wasPrice, price, rating } = req.body;

  //   console.log(req);

  if (
    [name, description, summery].some((field) => !field || field.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required");
  }

  if (!productId) throw new ApiError(400, "product Id isn't found!");

  console.log("price", price, typeof price);

  if (!price || !rating)
    throw new ApiError(400, " Price and Rating both are required");

  const product = await Product.findOne({ productId });

  if (!product)
    throw new ApiError(
      400,
      "Product not found! may be due to invalid product Id. Please check and try again"
    );

  product.name = name;
  product.description = description;
  product.summery = summery;
  product.price.currentPrice = price;
  product.rating = rating;

  if (wasPrice) product.price.wasPrice = wasPrice;

  await product.save();

  res.status(200).json(new ApiResponse(200, product, "Update completed"));
});

// Deletion of one product using product Id
const DeleteProduct = asyncHandler(async (req, res) => {
  const { productId } = req.params;

  // console.log(productId);

  if (!productId) throw new ApiError(400, "Product Id not found!");

  const DeletedProduct = await Product.findOneAndDelete(productId);

  if (!DeletedProduct)
    throw new ApiError(500, "failed to delete due to some internal error");

  res
    .status(200)
    .json(
      new ApiResponse(
        200,
        DeletedProduct,
        "Product deletion completed successfully"
      )
    );
});

export {
  AddImages,
  DeleteProduct,
  GetAllProducts,
  UploadNewProduct,
  GetProductDetails,
  UpdateProductDetails,
  ClearAndUpdateImages,
};
