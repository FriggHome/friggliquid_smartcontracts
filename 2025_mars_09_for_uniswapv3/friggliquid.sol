// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0; // Add this line

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@uniswap/v3-periphery/contracts/interfaces/ISwapRouter.sol";
import "./BytesLib.sol";



contract UniswapV3RouterProxy is Pausable, Ownable{
    using BytesLib for bytes;

    ISwapRouter public immutable uniswapRouter;
    uint256 public fee; // en basis points (100 = 1%)

    mapping(address => bool) public tokenAllowanceIsApproved;

    event FeeChanged(uint256 newFeePercentage);
    event Withdrawn(address indexed token, address indexed recipient, uint256 amount);
    event ExactInputSingleExecuted(address indexed user, address indexed tokenIn, address indexed tokenOut, uint256 feePool, uint256 amountIn, uint256 amountOut, uint256 fee);
    event ExactInputExecuted(address indexed user, address indexed tokenIn, uint256 amountIn, uint256 fee);

    constructor(address _uniswapRouter, uint256 _fee) Pausable() Ownable() {
        require(_fee <= 10000, "Fee too high"); // max 100%
        uniswapRouter = ISwapRouter(_uniswapRouter);
        fee = _fee;  // _fee is in basis points (100 = 1%)
    }

    /* --- Swaps ---*/

    function exactInputSingle(
        address tokenIn,
        address tokenOut,
        uint24 feePool_,
        address recipient,
        uint256 deadline,
        uint256 amountIn,
        uint256 amountOutMin,
        uint160 sqrtPriceLimitX96
    ) external whenNotPaused returns (uint256 amountOut) {
        require(amountIn > 0, "Amount must be greater than zero");

        uint256 amountInSubFee = amountIn - (amountIn * fee) / 10000;

        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        if (!tokenAllowanceIsApproved[tokenIn]){
            IERC20(tokenIn).approve(address(uniswapRouter),  type(uint256).max);
            tokenAllowanceIsApproved[tokenIn] = true;
        }

        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            fee: feePool_,
            recipient: recipient,
            deadline: deadline,
            amountIn: amountInSubFee,
            amountOutMinimum: amountOutMin,
            sqrtPriceLimitX96: sqrtPriceLimitX96
        });

        amountOut = uniswapRouter.exactInputSingle(params);
        emit ExactInputSingleExecuted(
            msg.sender,
            tokenIn,
            tokenOut,
            feePool_,
            amountIn,
            amountOut,
            fee
        );
    }

    function exactInputMulti(
        bytes memory path,
        address recipient,
        uint256 deadline,
        uint256 amountIn,
        uint256 amountOutMin
    ) external whenNotPaused returns (uint256 amountOut) {
        require(amountIn > 0, "Amount must be greater than zero");

        address tokenIn = path.toAddress(0);
        uint256 amountInSubFee = amountIn - (amountIn * fee) / 10000;

        IERC20(tokenIn).transferFrom(msg.sender, address(this), amountIn);
        if (!tokenAllowanceIsApproved[tokenIn]){
            IERC20(tokenIn).approve(address(uniswapRouter),  type(uint256).max);
            tokenAllowanceIsApproved[tokenIn] = true;
        }

        ISwapRouter.ExactInputParams memory params = ISwapRouter.ExactInputParams({
            path: path,
            recipient: recipient,
            deadline: deadline,
            amountIn: amountInSubFee,
            amountOutMinimum: amountOutMin
        });

        amountOut = uniswapRouter.exactInput(params);
        emit ExactInputExecuted(msg.sender, tokenIn, amountIn, fee);
    }

    /* --- Fee --- */

    function setFee(uint256 _newFee) external onlyOwner {
        require(_newFee <= 10000, "Fee too high");
        fee = _newFee;   // _fee is in basis points (100 = 1%)
        emit FeeChanged(_newFee);
    }

    function withdraw(address token, uint256 amount, address recipient) external onlyOwner {
        IERC20(token).transfer(recipient, amount);
        emit Withdrawn(token, recipient, amount);
    }

    /* --- Pause --- */

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}
