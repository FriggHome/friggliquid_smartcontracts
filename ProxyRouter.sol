// SPDX-License-Identifier: UNLICENSED
// Frighome.AI
// Fully Integrated Swap Router - version 2025/08/04
// tech@frigghome.com

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@uniswap/v3-periphery/contracts/interfaces/ISwapRouter.sol";
import "@uniswap/v3-periphery/contracts/interfaces/IQuoter.sol";
import "@uniswap/v3-periphery/contracts/interfaces/IQuoterV2.sol";
import "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import "./IWETH.sol";

using CurrencyLibrary for Currency;
using StateLibrary for IPoolManager;
import {Currency, CurrencyLibrary} from "@uniswap/v4-core/src/types/Currency.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {IUnlockCallback} from "@uniswap/v4-core/src/interfaces/callback/IUnlockCallback.sol";
import {StateLibrary} from "@uniswap/v4-core/src/libraries/StateLibrary.sol";
import {SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {IQuoter as IQuoterV3} from "@uniswap/v3-periphery/contracts/interfaces/IQuoter.sol"; 
import {IV4Quoter as IQuoterV4} from "@uniswap/v4-periphery/src/interfaces/IV4Quoter.sol";
import {SqrtPriceMath} from "@uniswap/v4-core/src/libraries/SqrtPriceMath.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {SwapMath} from "@uniswap/v4-core/src/libraries/SwapMath.sol";

interface ISwapRouter02Compatible {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        //uint256 deadline; âs sur base !!!
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    struct ExactInputParams {
        bytes path;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
    }

    function exactInputSingle(ExactInputSingleParams calldata params)
        external
        payable
        returns (uint256 amountOut);

    function exactInput(ExactInputParams calldata params)
        external
        payable
        returns (uint256 amountOut);

    function multicall(bytes[] calldata data)
        external
        payable
        returns (bytes[] memory results);

    function wrapETH(uint256 value) external payable;

    function unwrapWETH9(uint256 amountMinimum, address recipient) external payable;

    function sweepToken(
        address token,
        uint256 amountMinimum,
        address recipient
    ) external payable;
}


contract ProxyRouter is Pausable, Ownable, ReentrancyGuard, IUnlockCallback {
    using SafeERC20 for IERC20;
    using CurrencyLibrary for Currency;
    using PoolIdLibrary for PoolKey;

    enum DexType {
        UNISWAP_V3,
        PANCAKE_V3,
        UNISWAP_V4
    }

    struct SwapSegment {
        DexType dexType;
        address sc;
        address tokenIn;
        address tokenOut;
        uint24 fee;
        uint256 minAmountOut;
        bytes swapData;
    }

    struct MultiDexHybridParams {
        SwapSegment[] segments;
        address recipient;
        uint256 totalAmountIn;
        uint256 totalMinAmountOut;
        uint256 deadline;
    }

    struct V3SwapData {
        bytes path;
        uint256 deadline;
    }

    struct V4SwapData {
        PoolKey poolKey;
        bool zeroForOne;
        uint160 sqrtPriceLimitX96;
        bytes hookData;
        uint256 deadline;
    }

    struct V4SwapParams {
        PoolKey key;
        bool zeroForOne;
        int256 amountSpecified;
        uint160 sqrtPriceLimitX96;
        bytes hookData;
    }

    struct V4SwapCallbackData {
        address sender;
        address recipient;
        Currency currencyIn;
        Currency currencyOut;
        uint256 originalAmount;
        bool isExactInput;
        bool zeroForOne; 
        PoolKey poolKey;
    }

    IWETH private immutable weth;
    uint256 public fee;
    IPoolManager public immutable poolManagerV4;
    uint160 internal constant MIN_SQRT_RATIO = 4295128739;
    uint160 internal constant MAX_SQRT_RATIO = 1461446703485210103287273052203988822378723970342;
    bool private _emergencyUnlocked = false;

    modifier nonReentrantCustom() {
        require(!_emergencyUnlocked, "Contract emergency locked");
        _;
    }

    constructor(
        address _weth,
        uint256 _fee,
        address _poolManagerV4
    ) Ownable() {
        require(_fee <= 10000, "Fee too high");
        weth = IWETH(_weth);
        fee = _fee;
        poolManagerV4 = IPoolManager(_poolManagerV4);
    }

    function setFee(uint256 _newFee) external onlyOwner {
        require(_newFee <= 10000, "Fee too high");
        fee = _newFee;
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function emergencyUnlock() external onlyOwner {
        _emergencyUnlocked = false;
    }

    function withdraw(
        address token,
        uint256 amount,
        address recipient
    ) external onlyOwner nonReentrant {
        if (token == address(0)) {
            (bool success,) = payable(recipient).call{value: amount}("");
            require(success, "ETH transfer failed");
        } else {
            IERC20(token).safeTransfer(recipient, amount);
        }
    }

    function depositETH(address recipient) external payable whenNotPaused {
        require(msg.value > 0, "No ETH sent");
        require(recipient != address(0), "Invalid recipient");
        
        uint256 amountAfterFee = subtractFee(msg.value);
        
        weth.deposit{value: amountAfterFee}();
        IERC20(address(weth)).safeTransfer(recipient, amountAfterFee);
    }

    function withdrawWETH(uint256 amount, address recipient) external whenNotPaused nonReentrant {
        require(amount > 0, "Invalid amount");
        require(recipient != address(0), "Invalid recipient");
        
        IERC20(address(weth)).safeTransferFrom(msg.sender, address(this), amount);
        uint256 amountAfterFee = subtractFee(amount);
        weth.withdraw(amountAfterFee);
        
        (bool success,) = payable(recipient).call{value: amountAfterFee}("");
        require(success, "ETH transfer failed");
    }

    function toAddress(bytes memory _bytes, uint256 _start) internal pure returns (address) {
        require(_start + 20 >= _start, "toAddress_overflow");
        require(_bytes.length >= _start + 20, "toAddress_outOfBounds");
        address tempAddress;
        assembly {
            tempAddress := div(mload(add(add(_bytes, 0x20), _start)), 0x1000000000000000000000000)
        }
        return tempAddress;
    }

    function toUint24(bytes memory _bytes, uint256 _start) internal pure returns (uint24) {
        require(_start + 3 >= _start, "toUint24_overflow");
        require(_bytes.length >= _start + 3, "toUint24_outOfBounds");
        uint24 tempUint;
        assembly {
            tempUint := mload(add(add(_bytes, 0x3), _start))
        }
        return tempUint;
    }

    function bytesToHex(bytes memory data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(2 + data.length * 2);
        str[0] = "0";
        str[1] = "x";
        for (uint256 i = 0; i < data.length; i++) {
            str[2 + i * 2] = alphabet[uint256(uint8(data[i] >> 4))];
            str[3 + i * 2] = alphabet[uint256(uint8(data[i] & 0x0f))];
        }
        return string(str);
    }

    function addressToHexString(address addr) internal pure returns (string memory) {
        return Strings.toHexString(uint160(addr), 20);
    }

function calculateV4AmountOut(BalanceDelta delta, bool zeroForOne) internal pure returns (uint256) {
    if (zeroForOne) {
        return uint256(-int256(delta.amount1()));
    } else {
        return uint256(-int256(delta.amount0()));
    }
}


    function toCurrency(address token) internal pure returns (Currency) {
        return Currency.wrap(token);
    }

    function fromCurrency(Currency currency) internal pure returns (address) {
        return Currency.unwrap(currency);
    }

    function getSqrtPriceLimitForSwap(bool zeroForOne) internal pure returns (uint160) {
        return zeroForOne ? MIN_SQRT_RATIO + 1 : MAX_SQRT_RATIO - 1;
    }

    function subtractFee(uint256 amount) internal view returns (uint256) {
        return amount - (amount * fee / 10000);
    }


function _internalDecodeV3SwapData(bytes memory data, address token0, address token1, uint24 fee) internal view returns (V3SwapData memory result) {
    require(data.length >= 64, "Empty or too short");

    bytes32 firstWord;
    bytes32 secondWord;
    assembly {
        firstWord := mload(add(data, 32))
        secondWord := mload(add(data, 64))
    }

    uint256 pathOffset = uint256(firstWord);
    uint256 deadline = uint256(secondWord);

    require(pathOffset >= 64, "Invalid path offset");
    require(pathOffset + 32 <= data.length, "Offset overflow");

    uint256 pathLength;
    assembly {
        pathLength := mload(add(add(data, 32), pathOffset))
    }

    require(pathLength >= 43, "Path too short");
    require((pathLength - 20) % 23 == 0, "Invalid path length arithmetic");
    require(pathOffset + 32 + pathLength <= data.length, "Path out of bounds");

    bytes memory path = new bytes(pathLength);
    assembly {
        let src := add(add(add(data, 32), pathOffset), 32)
        let dst := add(path, 32)
        for { let i := 0 } lt(i, pathLength) { i := add(i, 1) } {
            mstore8(add(dst, i), byte(0, mload(add(src, i))))
        }
    }

    address firstToken;
    address lastToken;
    uint24 firstFee;

    assembly {
        firstToken := shr(96, mload(add(path, 32)))
        firstFee := shr(232, mload(add(add(path, 32), 20)))
        let lastTokenOffset := add(sub(pathLength, 20), 32)
        lastToken := shr(96, mload(add(path, lastTokenOffset)))
    }

    require(firstToken != address(0), "firstToken zero");
    require(lastToken != address(0), "lastToken zero");
    require(firstToken != lastToken, "tokens equal");
    require(firstToken == token0, "token0 mismatch");
    require(lastToken == token1, "token1 mismatch");
    require(firstFee == fee, "fee mismatch");

    require(deadline > block.timestamp, "deadline expired");
    require(deadline < block.timestamp + 365 days, "deadline too far");

    result = V3SwapData({ path: path, deadline: deadline });
}

    function _quoteV3Segment(
        SwapSegment memory segment,
        uint256 amountIn,
        address token0, address token1, uint24 fee
    ) internal returns (uint256 amountOut) {
        address contractAddress = segment.sc; // yes a special case it's not a router , just the same variable name
        require(contractAddress != address(0), "Quoter not set for router v3");
        
        V3SwapData memory v3Data = _internalDecodeV3SwapData(segment.swapData, token0, token1, fee);
        bytes memory path = v3Data.path;
        
        if (token0 == address(0)) {  
            token0 = address(weth);
            path = replaceAddress(path, 0, address(weth));
        }
        if (token1 == address(0)){
            token1 = address(weth);
            path = replaceAddress(path, path.length - 20, address(weth));
        }

        require(amountIn != 0, "Amount =0 v3");
        require(amountIn > 0, "Amount must be positive v3");
        require(v3Data.deadline >= block.timestamp, "Deadline expired v3");

        if (block.chainid == 8453) { // Base
            try IQuoterV2(contractAddress).quoteExactInput(path, amountIn) returns (
        uint256 amountOutRes,
        uint160[] memory sqrtPriceX96AfterList,
        uint32[] memory initializedTicksCrossedList,
                uint256 gasEstimate
            ) {
                return amountOutRes;
            } catch Error(string memory reason) {
                revert(string.concat("QuoterV2 multi failed V3: ", reason));
            } catch {
                revert("QuoterV2 multi unknown error");
            }
        } else {
            return IQuoterV3(contractAddress).quoteExactInput(path, amountIn);
        }
    }

    function quoteMultiDexHybrid(
        SwapSegment[] calldata segments,
        uint256 totalAmountIn
    ) external returns (uint256 totalAmountOut) {
        require(segments.length > 0, "No segments provided");
        
        uint256 amountAfterFee = subtractFee(totalAmountIn);
        require(amountAfterFee > 0, "Amount after fee must be positive");
        
        for (uint256 i = 0; i < segments.length; i++) {
            if (segments[i].dexType == DexType.UNISWAP_V4) {
                V4SwapData memory v4Data = abi.decode(segments[i].swapData, (V4SwapData));
                require(_isPoolInitialized(v4Data.poolKey), 
                    string.concat("Pool not initialized for quote at segment ", Strings.toString(i)));
            }
        }
        
        uint256 currentAmount = amountAfterFee;
        
        for (uint256 i = 0; i < segments.length; i++) {
            SwapSegment memory segment = segments[i];
            
            if (i > 0) {
                SwapSegment memory prevSegment = segments[i-1];
                require(
                    segment.tokenIn == prevSegment.tokenOut,
                    "Token mismatch between segments "
                );
            }
            
            if (segment.dexType == DexType.UNISWAP_V3 || segment.dexType == DexType.PANCAKE_V3) {
                currentAmount = _quoteV3Segment(segment, currentAmount, segment.tokenIn, segment.tokenOut, segment.fee);
            } else if (segment.dexType == DexType.UNISWAP_V4) {
                currentAmount = _quoteV4Segment(segment, currentAmount);
            } else {
                revert("Unsupported DEX type");
            }
        }
        
        return currentAmount;
    }

    function isL2Network() internal view returns (bool) {
    uint256 chainId = block.chainid;
    return (
        chainId == 42161 || // Arbitrum One
        chainId == 421614 || // Arbitrum Sepolia  
        chainId == 10 || // Optimism
        chainId == 8453 || // Base
        chainId == 137 || // Polygon
        chainId == 324 // zkSync Era
    );
    }

    function _bytes4ToHex(bytes4 data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(10);
        str[0] = "0"; str[1] = "x";
        for (uint i = 0; i < 4; i++) {
            str[2+i*2] = alphabet[uint(uint8(data[i] >> 4))];
            str[3+i*2] = alphabet[uint(uint8(data[i] & 0x0f))];
        }
        return string(str);
    }

    function _toHexChar(uint8 value) internal pure returns (bytes1) {
        return value < 10 ? bytes1(uint8(48 + value)) : bytes1(uint8(87 + value));
    }

    function directV4QuoteAdvanced(
    PoolKey memory poolKey,
    bool zeroForOne,
    uint128 exactAmount
    ) external view returns (uint256 amountOut) {
        require(exactAmount != 0, "Amount =0 v4");
        require(exactAmount > 0, "Amount must be positive v4");
        require(_isPoolInitialized(poolKey), "Pool not initialized for quote");
        
        PoolId poolId = poolKey.toId();
        
        uint160 sqrtPriceX96;
        uint128 liquidity;
        {
            (sqrtPriceX96,,,) = poolManagerV4.getSlot0(poolId);
            require(sqrtPriceX96 != 0, "Pool not initialized");
            
            liquidity = poolManagerV4.getLiquidity(poolId);
            require(liquidity > 0, "No liquidity");
        }
        
        {
            uint160 sqrtPriceLimitX96 = zeroForOne 
                ? uint160(MIN_SQRT_RATIO + 1)
                : uint160(MAX_SQRT_RATIO - 1);
            
            (,, uint256 amountOutCalculated,) = SwapMath.computeSwapStep(
                sqrtPriceX96,
                sqrtPriceLimitX96,
                liquidity,
                -int256(uint256(exactAmount)),
                poolKey.fee
            );
            
            return amountOutCalculated;
        }
    }


    function _quoteV4Segment(
        SwapSegment memory segment,
        uint256 amountIn
    ) internal returns (uint256 amountOut) {
        require(amountIn <= type(uint128).max, "Amount exceeds uint128 max");
        uint128 exactAmount = uint128(amountIn);
        V4SwapData memory v4Data = abi.decode(segment.swapData, (V4SwapData));
         
        require(exactAmount != 0, "exactAmount must be V4 = 0 ");
        require(exactAmount > 0, "exactAmount must be > 0 v4");
        require(v4Data.hookData.length <= 256, "hookData too large");
        require(_isPoolInitialized(v4Data.poolKey), "Pool not initialized for quote v4");
    
        address currency0 = Currency.unwrap(v4Data.poolKey.currency0);
        address currency1 = Currency.unwrap(v4Data.poolKey.currency1);
        require(
        currency0 < currency1,
        "Currency0 must be < Currency1"
    );
 
        require(v4Data.poolKey.tickSpacing > 0, "TickSpacing must be > 0");
        require(v4Data.poolKey.fee > 0, "Fee must be > 0");
        
        PoolKey memory newPoolKey = PoolKey({
            currency0: Currency.wrap(currency0), 
            currency1: Currency.wrap(currency1), 
            fee: v4Data.poolKey.fee,          
            tickSpacing: v4Data.poolKey.tickSpacing,     
            hooks: IHooks(v4Data.poolKey.hooks)
        });
        

        
        try this.directV4QuoteAdvanced(newPoolKey, v4Data.zeroForOne, exactAmount) returns (
            uint256 _amountOut
        ) {
            amountOut = _amountOut;
            return amountOut;
        } catch Error(string memory reason) {
            revert(string(abi.encodePacked("V4 Quote Error r: ", reason, " ")));
        } catch (bytes memory lowLevelData) {
            revert(
                string(
                    abi.encodePacked(
                        "V4 Quote Error l: ",
                        bytesToHex(lowLevelData),
                        " currency0: ",
                        addressToHexString(currency0),
                        " currency1: ",
                        addressToHexString(currency1),
                        " fee: "
                    )
                ) 
            );
        }
    }



    function executeMultiDexHybridSwap(
        MultiDexHybridParams calldata params,
        address sender
    ) external payable whenNotPaused nonReentrant returns (uint256 totalAmountOut) {
        require(params.segments.length > 0, "No segments provided");

        for (uint256 i = 0; i < params.segments.length; i++) {
        if (params.segments[i].dexType == DexType.UNISWAP_V4) {
            V4SwapData memory v4Data = abi.decode(params.segments[i].swapData, (V4SwapData));
            require(_isPoolInitialized(v4Data.poolKey), 
                string.concat("Pool v4 not initialized for quote at segment ", Strings.toString(i)));
        }
    }

        require(params.recipient != address(0), "Invalid recipient");
        require(params.deadline >= block.timestamp, "Deadline expired");
        
        uint256 currentAmount;
        
        address tokenIn = params.segments[0].tokenIn;
        if (tokenIn == address(0)) {
            require(msg.value == params.totalAmountIn, "Wrong ETH amount");
            weth.deposit{value: msg.value}();
           
        } 
        else
         {
             IERC20(tokenIn).safeTransferFrom(sender, address(this), params.totalAmountIn);
         }
        currentAmount = subtractFee(params.totalAmountIn);
        require(currentAmount>0, "Amount after fee must be positive");
        
        uint256 segmentsLength = params.segments.length;
        for (uint256 i = 0; i < segmentsLength;) {
            bool isLastSegment = (i == segmentsLength - 1);
            uint256 amountOutMinimum = 50;
            
            if (params.segments[i].dexType == DexType.UNISWAP_V3 || params.segments[i].dexType == DexType.PANCAKE_V3) {
                address tokenInUsed = params.segments[i].tokenIn == address(0) ? address(weth) : params.segments[i].tokenIn;
                uint256 allowance = IERC20(tokenInUsed).allowance(address(this), params.segments[i].sc);
                if (allowance < currentAmount) {
                    if (allowance != 0) {
                        IERC20(tokenInUsed).safeApprove(params.segments[i].sc, 0);
                    }
                    IERC20(tokenInUsed).safeApprove(params.segments[i].sc,currentAmount );
                }

                currentAmount = _executeV3SegmentOptimized(
                    params.segments[i],
                    currentAmount,
                    params.recipient,
                    isLastSegment,
                    amountOutMinimum
                );
                require(currentAmount >= amountOutMinimum, "hop - Insufficient output");
            } else if (params.segments[i].dexType == DexType.UNISWAP_V4) {
                currentAmount = _executeV4Segment(
                    params.segments[i],
                    currentAmount,
                    address(this),
                    params.recipient,
                    isLastSegment,
                    amountOutMinimum
                );
                require(currentAmount >= amountOutMinimum, "hop - Insufficient output");
            } else {
                revert("Unsupported DEX type");
            }
            
            unchecked { ++i; }
        }
        
        require(currentAmount >= params.totalMinAmountOut, "Insufficient output amount");
        
        address finalTokenOut = params.segments[segmentsLength - 1].tokenOut;
        if (finalTokenOut != address(0)) {
            IERC20(finalTokenOut).safeTransfer(params.recipient, currentAmount);
        } else {
            weth.withdraw(currentAmount);
            (bool success,) = payable(params.recipient).call{value: currentAmount}("");
            require(success, "ETH transfer failed");
        }
        
        return currentAmount;
    }

    function replaceAddress(
        bytes memory _bytes,
        uint256 _start,
        address _newAddress
    ) internal pure returns (bytes memory) {
        require(_bytes.length >= _start + 20, "replaceAddress_outOfBounds");
        
        assembly {
            let dataPtr := add(add(_bytes, 0x20), _start)
            mstore(dataPtr, or(and(mload(dataPtr), 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff), shl(96, _newAddress)))
        }
        
        return _bytes;
    }
function _validateTokenBeforeSwap(address token, uint256 amount) internal view {
    if (token == address(0) || token == address(weth)) return;
    
    uint256 codeSize;
    assembly { codeSize := extcodesize(token) }
    require(codeSize > 0, "Token is not a contract");
    
    try IERC20(token).totalSupply() returns (uint256 supply) {
        require(supply > 0, "Token has zero total supply");
        if (amount > 0) {
            require(amount <= supply / 10, "Amount exceeds 10% of supply");
        }
    } catch {
        revert("Invalid ERC20 token");
    }
}
function _isPoolInitialized(PoolKey memory poolKey) internal view returns (bool) {

    PoolId poolId = poolKey.toId();
    

    (uint160 sqrtPriceX96,,,) = poolManagerV4.getSlot0(poolId);
    return sqrtPriceX96 != 0;
}
    function _executeV3SegmentOptimized(
     
        SwapSegment memory segment,
        uint256 amountIn,
        address finalRecipient,
        bool isLastSegment,
        uint256 amountOutMinimum
     


    ) internal returns (uint256) {
        (bytes memory path, uint256 deadline) = abi.decode(segment.swapData, (bytes, uint256));
        require(deadline >= block.timestamp, "V3 deadline expired");
         _validateTokenBeforeSwap(segment.tokenIn, amountIn);
    _validateTokenBeforeSwap(segment.tokenOut, 0);

        address sc = segment.sc;
        address swapRecipient = address(this); 
        address tokenIn = segment.tokenIn;
        address tokenOut = segment.tokenOut;

        require(segment.fee >0, "Fee mismatch");


        if (tokenIn == address(0)) {  
            tokenIn = address(weth);
            path = replaceAddress(path, 0, address(weth));
        }
        if (tokenOut == address(0)){
            tokenOut = address(weth);
            path = replaceAddress(path, path.length - 20, address(weth));
        }

        
        if (block.chainid == 8453) { // Base 


    
     ISwapRouter02Compatible.ExactInputSingleParams memory paramsMemory = ISwapRouter02Compatible.ExactInputSingleParams({
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            fee: segment.fee,
            recipient: swapRecipient,
            //deadline: deadline, -- pas sur base!!
            amountIn: amountIn,
            amountOutMinimum: amountOutMinimum,
            sqrtPriceLimitX96: 0  
        });
        return ISwapRouter02Compatible(sc).exactInputSingle{value: 0}(paramsMemory);

    } else { 
        return ISwapRouter(sc).exactInput(
            ISwapRouter.ExactInputParams({
                path: path,
                recipient: swapRecipient,
                deadline: deadline,
                amountIn: amountIn,
                amountOutMinimum: amountOutMinimum
            })
        );
    }
    }

   function _executeV4Segment(
    SwapSegment memory segment,
    uint256 amountIn,
    address sender,
    address finalRecipient,
    bool isLastSegment,
    uint256 amountOutMinimum
) internal returns (uint256 amountOut) {
    V4SwapData memory v4Data = abi.decode(segment.swapData, (V4SwapData));
    require(v4Data.deadline >= block.timestamp, "V4 deadline expired");
    require(amountIn <= type(uint128).max, "Amount too large for V4");
    
    Currency currencyIn = toCurrency(segment.tokenIn == address(0) ? address(weth) : segment.tokenIn);
    Currency currencyOut = toCurrency(segment.tokenOut == address(0) ? address(weth) : segment.tokenOut);
    
             _validateTokenBeforeSwap(segment.tokenIn, amountIn);
    _validateTokenBeforeSwap(segment.tokenOut, 0);

    require(_isPoolInitialized(v4Data.poolKey), "Pool not initialized");
    
    V4SwapCallbackData memory callbackData = V4SwapCallbackData({
        sender: sender,
        recipient: isLastSegment ? finalRecipient : address(this),
        currencyIn: currencyIn,
        currencyOut: currencyOut,
        originalAmount: amountIn,
        isExactInput: true,
        zeroForOne: v4Data.zeroForOne,
        poolKey: v4Data.poolKey 
    });
    
    int256 amountSpecified = -int256(amountIn);
    
    bytes memory swapData = abi.encode(
        V4SwapParams({
            key: v4Data.poolKey,
            zeroForOne: v4Data.zeroForOne,
            amountSpecified: amountSpecified,
            sqrtPriceLimitX96: getSqrtPriceLimitForSwap(v4Data.zeroForOne),
            hookData: v4Data.hookData
        }),
        callbackData
    );
    
    try poolManagerV4.unlock(swapData) returns (bytes memory result) {
        amountOut = abi.decode(result, (uint256));
        require(amountOut >= amountOutMinimum, "V4 insufficient output");
        return amountOut;
    } catch (bytes memory lowLevelData) {
      
         revert(
                string(
                    abi.encodePacked(
                        "V4 swap failed: ",
                        bytesToHex(lowLevelData)
                       
                    )
                ) 
            );
    }
}
  


function _settle(Currency currency, uint256 amount) internal {
    if (currency.isAddressZero()) {

        poolManagerV4.settle{value: amount}();
    } else {
   
        address token = Currency.unwrap(currency);
        IERC20(token).safeTransfer(address(poolManagerV4), amount);
        poolManagerV4.sync(currency);
        poolManagerV4.settle();
    }
}

    function _take(Currency currency, address to, uint256 amount) internal {
        poolManagerV4.take(currency, to, amount);
    }

function _handleV4Deltas(BalanceDelta delta, V4SwapCallbackData memory callbackData) internal {
    int128 amount0Delta = delta.amount0();
    int128 amount1Delta = delta.amount1();
    
 
    if (amount0Delta > 0) {
        _settle(callbackData.zeroForOne ? callbackData.currencyIn : callbackData.currencyOut, uint128(amount0Delta));
    } else if (amount0Delta < 0) {
        _take(callbackData.zeroForOne ? callbackData.currencyOut : callbackData.currencyIn, callbackData.recipient, uint128(-amount0Delta));
    }
    
  
    if (amount1Delta > 0) {
        _settle(callbackData.zeroForOne ? callbackData.currencyOut : callbackData.currencyIn, uint128(amount1Delta));
    } else if (amount1Delta < 0) {
        _take(callbackData.zeroForOne ? callbackData.currencyIn : callbackData.currencyOut, callbackData.recipient, uint128(-amount1Delta));
    }
}

    function unlockCallback(bytes calldata data) external override returns (bytes memory) {
        require(msg.sender == address(poolManagerV4), "Only pool manager");
        
        string memory operationType = abi.decode(data, (string));
        bytes32 opHash = keccak256(abi.encodePacked(operationType));
        
        if (opHash == keccak256("QUOTE")) {
            return _handleQuoteCallback(data);
        } else {
            return _handleSwapCallback(data);
        }
    }

    function _handleQuoteCallback(bytes calldata data) internal returns (bytes memory) {
        (, PoolKey memory poolKey, bool zeroForOne, int256 amountSpecified) = 
            abi.decode(data, (string, PoolKey, bool, int256));
        
        SwapParams memory swapParams = SwapParams({
            zeroForOne: zeroForOne,
            amountSpecified: amountSpecified,
            sqrtPriceLimitX96: getSqrtPriceLimitForSwap(zeroForOne)
        });
        
        BalanceDelta delta = poolManagerV4.swap(poolKey, swapParams, "");
        
        uint256 amountOut;
        if (zeroForOne) {
            amountOut = uint256(-int256(delta.amount1()));
        } else {
            amountOut = uint256(-int256(delta.amount0()));
        }
        
        return abi.encode(amountOut);
    }

    function _handleSwapCallback(bytes calldata data) internal returns (bytes memory) {
        (V4SwapParams memory swapParams, V4SwapCallbackData memory callbackData) = 
            abi.decode(data, (V4SwapParams, V4SwapCallbackData));

        SwapParams memory poolManagerParams = SwapParams({
            zeroForOne: swapParams.zeroForOne,
            amountSpecified: swapParams.amountSpecified,
            sqrtPriceLimitX96: swapParams.sqrtPriceLimitX96
        });

        BalanceDelta delta = poolManagerV4.swap(
            swapParams.key,
            poolManagerParams,
            swapParams.hookData
        );
        
        _handleV4Deltas(delta, callbackData);
        uint256 amountOut = calculateV4AmountOut(delta, swapParams.zeroForOne);
        
   
        return abi.encode(amountOut);
    }

    

 
    function getWETHAddress() external view returns (address) {
        return address(weth);
    }

    function canReceiveERC20(address recipient) external view returns (bool) {
        if (recipient == address(0)) return false;
        
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(recipient)
        }
        
        if (codeSize == 0) return true;
        return true;
    }

    receive() external payable {}
}
