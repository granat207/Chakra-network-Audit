// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

//run this test --> sudo forge test --match-path AuditTest/HandlerTest/ChakraSettlementHandlerTest.t.sol 

import {Test, console} from "forge-std/Test.sol"; 

import {ChakraSettlementHandler} from "../../../solidity/handler/contracts/ChakraSettlementHandler.sol"; 

contract ChakraSettlementHandlerTest is Test{

ChakraSettlementHandler public chakraSettlementHandler; 

address public owner; 

function setUp() public {
owner = address(this); 
chakraSettlementHandler = new ChakraSettlementHandler(); 
}

// function test_startingVariables() public view {
// assertEq(chakraSettlementHandler.token(), 0); 
// }
}