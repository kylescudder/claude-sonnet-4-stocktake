// Stock Keeping API - Express.js with MongoDB
// This is a comprehensive inventory management system

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB Schemas
const productSchema = new mongoose.Schema({
  sku: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  description: String,
  category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category' },
  brand: String,
  unit: { type: String, default: 'piece' },
  weight: Number,
  dimensions: {
    length: Number,
    width: Number,
    height: Number
  },
  images: [String],
  active: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const warehouseSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  address: {
    street: String,
    city: String,
    state: String,
    country: String,
    zipCode: String
  },
  capacity: Number,
  manager: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  active: { type: Boolean, default: true }
});

const inventorySchema = new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  warehouse: { type: mongoose.Schema.Types.ObjectId, ref: 'Warehouse', required: true },
  quantity: { type: Number, default: 0 },
  reservedQuantity: { type: Number, default: 0 },
  reorderPoint: { type: Number, default: 10 },
  reorderQuantity: { type: Number, default: 50 },
  lastRestocked: Date,
  location: {
    zone: String,
    aisle: String,
    shelf: String,
    bin: String
  }
}, { 
  indexes: [
    { product: 1, warehouse: 1 },
    { quantity: 1 },
    { 'location.zone': 1 }
  ]
});

const stockMovementSchema = new mongoose.Schema({
  type: { 
    type: String, 
    enum: ['IN', 'OUT', 'TRANSFER', 'ADJUSTMENT', 'RETURN'], 
    required: true 
  },
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  fromWarehouse: { type: mongoose.Schema.Types.ObjectId, ref: 'Warehouse' },
  toWarehouse: { type: mongoose.Schema.Types.ObjectId, ref: 'Warehouse' },
  quantity: { type: Number, required: true },
  reference: String,
  reason: String,
  performedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});

const categorySchema = new mongoose.Schema({
  name: { type: String, required: true },
  parent: { type: mongoose.Schema.Types.ObjectId, ref: 'Category' },
  description: String
});

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: String,
  role: { type: String, enum: ['admin', 'manager', 'staff'], default: 'staff' },
  active: { type: Boolean, default: true }
});

// Models
const Product = mongoose.model('Product', productSchema);
const Warehouse = mongoose.model('Warehouse', warehouseSchema);
const Inventory = mongoose.model('Inventory', inventorySchema);
const StockMovement = mongoose.model('StockMovement', stockMovementSchema);
const Category = mongoose.model('Category', categorySchema);
const User = mongoose.model('User', userSchema);

// Middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) throw new Error();
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    const user = await User.findById(decoded.id).select('-password');
    if (!user || !user.active) throw new Error();
    
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Please authenticate' });
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    next();
  };
};

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = new User({ email, password: hashedPassword, name, role });
    await user.save();
    
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'secret');
    res.status(201).json({ token, user: { id: user._id, email, name, role } });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, active: true });
    
    if (!user || !await bcrypt.compare(password, user.password)) {
      throw new Error('Invalid credentials');
    }
    
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || 'secret');
    res.json({ token, user: { id: user._id, email, name: user.name, role: user.role } });
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

// Product Routes
app.get('/api/products', authenticate, async (req, res) => {
  try {
    const { category, active, search, page = 1, limit = 20 } = req.query;
    const query = {};
    
    if (category) query.category = category;
    if (active !== undefined) query.active = active === 'true';
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { sku: { $regex: search, $options: 'i' } },
        { brand: { $regex: search, $options: 'i' } }
      ];
    }
    
    const products = await Product.find(query)
      .populate('category')
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ createdAt: -1 });
    
    const count = await Product.countDocuments(query);
    
    res.json({
      products,
      totalPages: Math.ceil(count / limit),
      currentPage: page,
      total: count
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/products', authenticate, authorize('admin', 'manager'), async (req, res) => {
  try {
    const product = new Product(req.body);
    await product.save();
    res.status(201).json(product);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put('/api/products/:id', authenticate, authorize('admin', 'manager'), async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      { ...req.body, updatedAt: Date.now() },
      { new: true, runValidators: true }
    );
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json(product);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Warehouse Routes
app.get('/api/warehouses', authenticate, async (req, res) => {
  try {
    const warehouses = await Warehouse.find({ active: true }).populate('manager', 'name email');
    res.json(warehouses);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/warehouses', authenticate, authorize('admin'), async (req, res) => {
  try {
    const warehouse = new Warehouse(req.body);
    await warehouse.save();
    res.status(201).json(warehouse);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Inventory Routes
app.get('/api/inventory', authenticate, async (req, res) => {
  try {
    const { warehouse, product, lowStock, page = 1, limit = 20 } = req.query;
    const query = {};
    
    if (warehouse) query.warehouse = warehouse;
    if (product) query.product = product;
    if (lowStock === 'true') {
      query.$expr = { $lte: ['$quantity', '$reorderPoint'] };
    }
    
    const inventory = await Inventory.find(query)
      .populate('product')
      .populate('warehouse')
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ quantity: 1 });
    
    const count = await Inventory.countDocuments(query);
    
    res.json({
      inventory,
      totalPages: Math.ceil(count / limit),
      currentPage: page,
      total: count
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/inventory/:productId/:warehouseId', authenticate, async (req, res) => {
  try {
    const inventory = await Inventory.findOne({
      product: req.params.productId,
      warehouse: req.params.warehouseId
    }).populate('product warehouse');
    
    if (!inventory) return res.status(404).json({ error: 'Inventory record not found' });
    res.json(inventory);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Stock Movement Routes
app.post('/api/stock-movements', authenticate, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const { type, product, fromWarehouse, toWarehouse, quantity, reference, reason } = req.body;
    
    // Validate quantity
    if (quantity <= 0) throw new Error('Quantity must be positive');
    
    // Create movement record
    const movement = new StockMovement({
      type,
      product,
      fromWarehouse,
      toWarehouse,
      quantity,
      reference,
      reason,
      performedBy: req.user._id
    });
    
    // Update inventory based on movement type
    switch (type) {
      case 'IN':
        await Inventory.findOneAndUpdate(
          { product, warehouse: toWarehouse },
          { 
            $inc: { quantity },
            $set: { lastRestocked: Date.now() }
          },
          { upsert: true, session }
        );
        break;
        
      case 'OUT':
        const fromInv = await Inventory.findOne({ product, warehouse: fromWarehouse }).session(session);
        if (!fromInv || fromInv.quantity < quantity) {
          throw new Error('Insufficient stock');
        }
        await Inventory.findOneAndUpdate(
          { product, warehouse: fromWarehouse },
          { $inc: { quantity: -quantity } },
          { session }
        );
        break;
        
      case 'TRANSFER':
        const sourceInv = await Inventory.findOne({ product, warehouse: fromWarehouse }).session(session);
        if (!sourceInv || sourceInv.quantity < quantity) {
          throw new Error('Insufficient stock for transfer');
        }
        
        await Inventory.findOneAndUpdate(
          { product, warehouse: fromWarehouse },
          { $inc: { quantity: -quantity } },
          { session }
        );
        
        await Inventory.findOneAndUpdate(
          { product, warehouse: toWarehouse },
          { $inc: { quantity } },
          { upsert: true, session }
        );
        break;
        
      case 'ADJUSTMENT':
        const targetWarehouse = fromWarehouse || toWarehouse;
        const adjustmentQty = fromWarehouse ? -quantity : quantity;
        
        await Inventory.findOneAndUpdate(
          { product, warehouse: targetWarehouse },
          { $inc: { quantity: adjustmentQty } },
          { upsert: true, session }
        );
        break;
    }
    
    await movement.save({ session });
    await session.commitTransaction();
    
    res.status(201).json(movement);
  } catch (error) {
    await session.abortTransaction();
    res.status(400).json({ error: error.message });
  } finally {
    session.endSession();
  }
});

app.get('/api/stock-movements', authenticate, async (req, res) => {
  try {
    const { product, warehouse, type, startDate, endDate, page = 1, limit = 50 } = req.query;
    const query = {};
    
    if (product) query.product = product;
    if (warehouse) {
      query.$or = [{ fromWarehouse: warehouse }, { toWarehouse: warehouse }];
    }
    if (type) query.type = type;
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }
    
    const movements = await StockMovement.find(query)
      .populate('product', 'name sku')
      .populate('fromWarehouse', 'name code')
      .populate('toWarehouse', 'name code')
      .populate('performedBy', 'name email')
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .sort({ createdAt: -1 });
    
    const count = await StockMovement.countDocuments(query);
    
    res.json({
      movements,
      totalPages: Math.ceil(count / limit),
      currentPage: page,
      total: count
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Reports Routes
app.get('/api/reports/low-stock', authenticate, async (req, res) => {
  try {
    const lowStockItems = await Inventory.find({
      $expr: { $lte: ['$quantity', '$reorderPoint'] }
    })
    .populate('product', 'name sku')
    .populate('warehouse', 'name code')
    .sort({ quantity: 1 });
    
    res.json(lowStockItems);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/reports/stock-value', authenticate, authorize('admin', 'manager'), async (req, res) => {
  try {
    const { warehouse } = req.query;
    const match = warehouse ? { warehouse: mongoose.Types.ObjectId(warehouse) } : {};
    
    const stockValue = await Inventory.aggregate([
      { $match: match },
      {
        $lookup: {
          from: 'products',
          localField: 'product',
          foreignField: '_id',
          as: 'productInfo'
        }
      },
      { $unwind: '$productInfo' },
      {
        $lookup: {
          from: 'warehouses',
          localField: 'warehouse',
          foreignField: '_id',
          as: 'warehouseInfo'
        }
      },
      { $unwind: '$warehouseInfo' },
      {
        $group: {
          _id: '$warehouse',
          warehouseName: { $first: '$warehouseInfo.name' },
          totalItems: { $sum: '$quantity' },
          uniqueProducts: { $addToSet: '$product' }
        }
      },
      {
        $project: {
          warehouse: '$_id',
          warehouseName: 1,
          totalItems: 1,
          uniqueProducts: { $size: '$uniqueProducts' }
        }
      }
    ]);
    
    res.json(stockValue);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/reports/movement-summary', authenticate, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const dateQuery = {};
    
    if (startDate) dateQuery.$gte = new Date(startDate);
    if (endDate) dateQuery.$lte = new Date(endDate);
    
    const summary = await StockMovement.aggregate([
      {
        $match: dateQuery.createdAt ? { createdAt: dateQuery } : {}
      },
      {
        $group: {
          _id: {
            type: '$type',
            date: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }
          },
          count: { $sum: 1 },
          totalQuantity: { $sum: '$quantity' }
        }
      },
      {
        $sort: { '_id.date': -1 }
      }
    ]);
    
    res.json(summary);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Batch Operations
app.post('/api/batch/import-products', authenticate, authorize('admin'), async (req, res) => {
  try {
    const { products } = req.body;
    const results = await Product.insertMany(products, { ordered: false });
    res.json({ imported: results.length });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/batch/stock-take', authenticate, authorize('admin', 'manager'), async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const { adjustments } = req.body; // Array of { product, warehouse, actualQuantity }
    const movements = [];
    
    for (const adj of adjustments) {
      const current = await Inventory.findOne({
        product: adj.product,
        warehouse: adj.warehouse
      }).session(session);
      
      if (!current) continue;
      
      const difference = adj.actualQuantity - current.quantity;
      if (difference !== 0) {
        const movement = new StockMovement({
          type: 'ADJUSTMENT',
          product: adj.product,
          fromWarehouse: difference < 0 ? adj.warehouse : null,
          toWarehouse: difference > 0 ? adj.warehouse : null,
          quantity: Math.abs(difference),
          reason: 'Stock take adjustment',
          performedBy: req.user._id
        });
        
        await movement.save({ session });
        movements.push(movement);
        
        await Inventory.findOneAndUpdate(
          { product: adj.product, warehouse: adj.warehouse },
          { quantity: adj.actualQuantity },
          { session }
        );
      }
    }
    
    await session.commitTransaction();
    res.json({ adjustments: movements.length, movements });
  } catch (error) {
    await session.abortTransaction();
    res.status(400).json({ error: error.message });
  } finally {
    session.endSession();
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date() });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Database connection and server start
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/stockkeeping';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('Connected to MongoDB');
  app.listen(PORT, () => {
    console.log(`Stock Keeping API running on port ${PORT}`);
  });
})
.catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});
