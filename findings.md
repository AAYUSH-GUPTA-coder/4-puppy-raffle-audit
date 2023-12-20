### [M-#] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle` is a potential denial of service (DoS) attack, incrementing gas costs for future entrants.

**Description:** The `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicates. However, the longer the `PuppyRaffle::Players` array is, the more checks a new player will have to make. This means the gas costs for players who enter right when the raffle stats will be dramatically lower than those whose enter later. Every Additional address in the `players` array, is an aadditional check the loop will have to make.

```javascript
// @audit DoS Attack
@>      for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```

**Imapct:** The gas costs for raffle entrants will grately incraese as more players enter the raffle. Discourging later users from entering, and cauisng a rush at the start of a raffle to be one of the first entrats in the queue.

An attacker might make the `PuppyRaffle::entrants` arrays so big, that no one else enters, guarenteeing themselves the win.

**Proof of Concept:**
if we have 2 sets of 100 players enter, the gas costs will be as such:
- 1st 100 players: 6254372
- 2nd 100 players: 18070466

This is more than 3x more expensive for the second 100 players

<details>
<summary?>PoC</summary>
Place the following test into `PuppyRaffleTest.t.sol`

```javascript
function testDosAttack() public {
        vm.txGasPrice(1);
        uint160 playersNum = 100;
        address[] memory newPlayers = new address[](playersNum);
        for (uint160 i; i < playersNum; i++) {
            newPlayers[i] = address(i);
        }
        uint256 gasStart = gasleft();
        address user = makeAddr("user");
        vm.deal(user, 1000000 ether);
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(newPlayers);
        uint256 gasEnd = gasleft();
        uint256 gasUsedFirst = (gasStart - gasEnd) * tx.gasprice;
        uint256 gasUsedFirst1 = (gasStart - gasEnd);
        console.log("Gas cost of the first 100 players: ", gasUsedFirst);

        // now for the second 100 people
        address[] memory newPlayers2 = new address[](playersNum);
        for (uint160 i; i < playersNum; i++) {
            newPlayers[i] = address(i + playersNum);
        }
        uint256 gasStart2 = gasleft();
        address user2 = makeAddr("user2");
        vm.deal(user2, 1000000 ether);
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(newPlayers);
        uint256 gasEnd2 = gasleft();
        uint256 gasUsedSecond = (gasStart2 - gasEnd2) * tx.gasprice;
        uint256 gasUsedSecond1 = (gasStart2 - gasEnd2);
        console.log("Gas cost of the first 100 players: ", gasUsedSecond);

        assert((gasUsedFirst * 2) < gasUsedSecond);
    }
```
</details>

**Recommended Mitigation** There are a few recomendations.
1. Consider allowing duplicates. Users can make new wallet addresses anyways, so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address.
2. Consider using a mapping to check for duplicates. This would allow constant time lookup of whether a user has already entered.

```diff
+  mapping(address => uint256) public addressToRaffleId;
+  uint256 public raffleId = 0;
    .
    .
    .
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
            addressToRaffleId[newPlayers[i]] = raffleId;
        }
       
+       // Check for duplicates only from the new players
+        for(uint256 i=0; i < newPlayers.length; i++){
+            require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle: Duplicate player");
+        }


-        // Check for duplicates
-        for (uint256 i = 0; i < players.length - 1; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
-                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-            }
-        }


        emit RaffleEnter(newPlayers);
    }
```

Alternatively, you can use [Openzeppelin's Enumerable Library](https://docs.openzeppelin.com/contracts/4.x/api/utils#EnumerableSet)