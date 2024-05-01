from fastapi import APIRouter, Request, Response, HTTPException
from pydantic import BaseModel, model_validator, ValidationError
from dtos.commitment import SequencerCommitment, CommitmentResponse
from utils.deserializers import (
    deserialize_commitments,
    deserialize_to_commitment_response,
)
from config import CONFIG

from services.l2_rpc import L2RpcClient

import random

router = APIRouter(
    prefix="/v1/batch",
    tags=["Batch"],
    responses={404: {"description": "Not found"}},
)


l2_rpc_client = L2RpcClient()


@router.get("/commitments", response_model=list[CommitmentResponse])
async def get_batches(request: Request, page: int = 1, limit: int = 10):
    async with request.app.async_pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT * 
                FROM sequencer_commitments
                ORDER BY id DESC
                LIMIT %s OFFSET %s
            """,
                (limit, (page - 1) * limit),
            )
            return deserialize_to_commitment_response(await cur.fetchall())


class SearchParam(BaseModel):
    hash: str | None = None
    height: int | None = None

    @model_validator(
        mode="before"
    )  # `pre=True` to check this before any other validation
    def check_exclusivity(cls, values):
        hash_, height = values.get("hash"), values.get("height")
        if (hash_ is None and height is None) or (
            hash_ is not None and height is not None
        ):
            raise ValidationError(
                "Either 'hash' or 'height' must be provided, but not both."
            )
        return values


# this will take either  block hash or block height
@router.post("/l2-block-status")
async def get_l2_block_status(request: Request, search_param: SearchParam):
    height = None
    if search_param.hash:
        l2_block_hash = search_param.hash
        block = await l2_rpc_client.get_l2_block_by_hash(l2_block_hash)
        if block is None:
            return Response(status_code=400, content="Invalid block hash")
        if block["result"]:
            try:
                # add res result null check
                height = int(block["result"]["number"], 16)
            except Exception as e:
                return Response(status_code=400, content="Invalid block hash or height")
    elif search_param.height:
        height = search_param.height
    try:
        async with request.app.async_pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                        SELECT *
                        FROM sequencer_commitments
                        WHERE l2_start_height <= %s AND l2_end_height >= %s
                    """,
                    (height, height),
                )
                results = deserialize_commitments(await cur.fetchall())
                return results[0].status
    except Exception as e:
        return Response(status_code=400, content="Invalid block hash or height")


if CONFIG.env == "test":

    @router.post("/test-generate-data")
    async def generate_data(request: Request):

        def random_sequencer_commitments():

            l1_start_height = 1
            l1_end_height = 2
            l2_start_height = 1
            l2_end_height = 20

            def random_64_hex_str():
                return str("%030x" % random.randrange(16**64))

            for i in range(10):
                yield SequencerCommitment(
                    l1_start_height=l1_start_height,
                    l1_end_height=l1_end_height,
                    l1_tx_id=random_64_hex_str(),
                    l1_start_hash=random_64_hex_str(),
                    l1_end_hash=random_64_hex_str(),
                    l2_start_height=l2_start_height,
                    l2_end_height=l2_end_height,
                    merkle_root=random_64_hex_str(),
                    status="pending",
                )
                l1_start_height += 1
                l1_end_height += 1
                l2_start_height += 20
                l2_end_height += 20

        async with request.app.async_pool.connection() as conn:
            cur = conn.cursor()
            async with conn.transaction():
                await cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS sequencer_commitments (
                        id                  SERIAL PRIMARY KEY,
                        l1_start_height     INT NOT NULL,
                        l1_end_height       INT NOT NULL,
                        l1_tx_id            VARCHAR(66) NOT NULL,
                        l1_start_hash       VARCHAR(66) NOT NULL,
                        l1_end_hash         VARCHAR(66) NOT NULL,
                        l2_start_height     INT NOT NULL,
                        l2_end_height       INT NOT NULL,
                        merkle_root         VARCHAR(66) NOT NULL,
                        status              VARCHAR(15) NOT NULL
                    );
                    """
                )
                rand_data = random_sequencer_commitments()
                for rd in rand_data:
                    await cur.execute(
                        """
                        INSERT INTO sequencer_commitments (l1_start_height, l1_end_height, l1_tx_id, l1_start_hash, l1_end_hash, l2_start_height, l2_end_height, merkle_root, status) 
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
                        """,
                        (
                            rd.l1_start_height,
                            rd.l1_end_height,
                            rd.l1_tx_id,
                            rd.l1_start_hash,
                            rd.l1_end_hash,
                            rd.l2_start_height,
                            rd.l2_end_height,
                            rd.merkle_root,
                            rd.status,
                        ),
                    )
