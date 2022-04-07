import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { expect } from "chai";
import { BigNumber } from "ethers";
import { ethers } from "hardhat";
import { Airdrop, MockToken } from "../typechain";
import { MerkleTree } from "merkletreejs";

let account1: SignerWithAddress;
let account2: SignerWithAddress;
let rest: SignerWithAddress[];
let merkleRoot: string;
let tree: MerkleTree;

let mockToken: MockToken;
let airdrop: Airdrop;

const airdropAmount = BigNumber.from("1000");

const getEIP712Domain = async () => {
  const chainId = (await ethers.provider.getNetwork()).chainId;

  return {
    name: "Airdrop",
    version: "v1",
    chainId,
    verifyingContract: airdrop.address,
  };
};

const signClaim = async (
  claimer: string,
  amount: BigNumber,
  signer: SignerWithAddress
) => {
  const EIP712Domain = await getEIP712Domain();

  const types = {
    Claim: [
      { name: "claimer", type: "address" },
      { name: "amount", type: "uint256" },
    ],
  };

  const value = { claimer, amount };
  const signature = await signer._signTypedData(EIP712Domain, types, value);

  return signature;
};

describe("Airdrop", function () {
  before(async () => {
    [account1, account2, ...rest] = await ethers.getSigners();

    mockToken = (await (
      await ethers.getContractFactory("MockToken")
    ).deploy("ERC20 Token", "ERC")) as MockToken;
    await mockToken.deployed();

    const leaves = rest.map((account) =>
      ethers.utils.keccak256(
        ethers.utils.defaultAbiCoder.encode(
          ["tuple(address, uint256)"],
          [[account.address, airdropAmount]]
        )
      )
    );

    tree = new MerkleTree(leaves, ethers.utils.keccak256, {
      sort: true,
    });
    merkleRoot = tree.getHexRoot();
  });

  beforeEach(async () => {
    airdrop = await (
      await ethers.getContractFactory("Airdrop")
    ).deploy(merkleRoot, account1.address, mockToken.address);

    await airdrop.deployed();

    // increase balance of airdrop contract. it will be used as treasury.
    const amount = BigNumber.from("10").pow(24);
    await mockToken.transfer(airdrop.address, amount);
  });

  describe("setup and disabling ECDSA", () => {
    it("should deploy correctly", async () => {
      // eslint-disable-next-line no-unused-expressions
      expect(ethers.utils.isAddress(airdrop.address)).to.be.true;

      expect(await airdrop.erc20Token()).to.be.eq(mockToken.address);
      expect(await airdrop.merkleRoot()).to.be.eq(merkleRoot);
      expect(await airdrop.isECDSADisabled()).to.be.eq(false);
    });

    it("should disable ECDSA verification", async () => {
      // first try with non-owner user
      await expect(
        airdrop.connect(account2).disableECDSAVerification()
      ).to.be.revertedWith("Ownable: caller is not the owner");

      // now try with owner
      await expect(airdrop.disableECDSAVerification())
        .to.emit(airdrop, "ECDSADisabled")
        .withArgs(account1.address);
    });
  });

  describe("Merkle claiming", () => {
    it("Should claim token with leaf", async () => {
      const claimer = rest[0];

      const leaf = ethers.utils.keccak256(
        ethers.utils.defaultAbiCoder.encode(
          ["tuple(address, uint256)"],
          [[claimer.address, airdropAmount]]
        )
      );
      const proof = tree.getHexProof(leaf);

      const initialClaimerBalance = await mockToken.balanceOf(claimer.address);

      await airdrop
        .connect(claimer)
        .merkleClaim(proof, leaf, claimer.address, airdropAmount);

      expect(await mockToken.balanceOf(claimer.address)).to.be.eq(
        initialClaimerBalance.add(airdropAmount)
      );
    });

    it("Should not claim token with invalid leaf", async () => {
      const claimer = rest[0];

      const leaf = ethers.utils.keccak256(
        ethers.utils.defaultAbiCoder.encode(
          ["tuple(address, uint256)"],
          [[claimer.address, airdropAmount]]
        )
      );
      const proof = tree.getHexProof(leaf);

      await expect(
        airdrop
          .connect(claimer)
          .merkleClaim(proof, leaf, claimer.address, airdropAmount.add(1))
      ).to.revertedWith("INVALID_LEAF");
    });

    it("Should not claim token if leaf does not exist (Invalid merkle root)", async () => {
      const claimer = account1;

      const leaf = ethers.utils.keccak256(
        ethers.utils.defaultAbiCoder.encode(
          ["tuple(address, uint256)"],
          [[claimer.address, airdropAmount]]
        )
      );
      const proof = tree.getHexProof(leaf);

      await expect(
        airdrop
          .connect(claimer)
          .merkleClaim(proof, leaf, claimer.address, airdropAmount)
      ).to.revertedWith("INVALID_MERKLE_ROOT");
    });

    it("Should not claim token if claimer has already claimed", async () => {
      const claimer = rest[0];

      const leaf = ethers.utils.keccak256(
        ethers.utils.defaultAbiCoder.encode(
          ["tuple(address, uint256)"],
          [[claimer.address, airdropAmount]]
        )
      );
      const proof = tree.getHexProof(leaf);

      await airdrop
        .connect(claimer)
        .merkleClaim(proof, leaf, claimer.address, airdropAmount);
      await expect(
        airdrop
          .connect(claimer)
          .merkleClaim(proof, leaf, claimer.address, airdropAmount)
      ).to.revertedWith("Already claimed");
    });

    it("Should not claim token of other claimer", async () => {
      const claimer = rest[0];

      const leaf = ethers.utils.keccak256(
        ethers.utils.defaultAbiCoder.encode(
          ["tuple(address, uint256)"],
          [[claimer.address, airdropAmount]]
        )
      );
      const proof = tree.getHexProof(leaf);

      await expect(
        airdrop
          .connect(account1)
          .merkleClaim(proof, leaf, claimer.address, airdropAmount)
      ).to.revertedWith("Invalid Sender");
    });
  });

  describe("Signature claiming", () => {
    it("should claim tokens with sig", async () => {
      const claimer = account2;
      const signer = account1;
      const signature = await signClaim(claimer.address, airdropAmount, signer);

      const initialClaimerBalance = await mockToken.balanceOf(claimer.address);

      await airdrop
        .connect(claimer)
        .signatureClaim(signature, account2.address, airdropAmount);

      expect(await mockToken.balanceOf(claimer.address)).to.be.eq(
        initialClaimerBalance.add(airdropAmount)
      );
    });

    it("should not claim tokens if sig is disabled", async () => {
      const claimer = account2;
      const signer = account1;
      const signature = await signClaim(claimer.address, airdropAmount, signer);

      await airdrop.disableECDSAVerification();

      await expect(
        airdrop
          .connect(claimer)
          .signatureClaim(signature, account2.address, airdropAmount)
      ).to.revertedWith("SIGS_DISABLED");
    });

    it("should not claim sig is not valid", async () => {
      const claimer = account2;
      const signer = account1;
      const signature = await signClaim(
        claimer.address,
        airdropAmount.add(1),
        signer
      );

      await expect(
        airdrop
          .connect(claimer)
          .signatureClaim(signature, account2.address, airdropAmount)
      ).to.revertedWith("INVALID_SIGNER");
    });
  });
});
