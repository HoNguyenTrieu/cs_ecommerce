const productController = require("../controllers/productController");

const router = require("express").Router();

router
  .route("/products")
  .get(productController.getProducts)
  .post(productController.createProduct);

router
  .route("/products/:id")
  .delete(productController.deleteProduct)
  .put(productController.updateProduct);

module.exports = router;
