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

import os
os.urandom


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
        height = block.number
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

            def random_32_byte_array():
                return str("%030x" % random.randrange(16**32))

            for i in range(10):
                yield SequencerCommitment(
                    l1_start_height=l1_start_height,
                    l1_end_height=l1_end_height,
                    l1_tx_id=random_32_byte_array(),
                    l1_start_hash=random_32_byte_array(),
                    l1_end_hash=random_32_byte_array(),
                    l2_start_height=l2_start_height,
                    l2_end_height=l2_end_height,
                    merkle_root=random_32_byte_array(),
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
                        l1_start_height     OID NOT NULL,
                        l1_end_height       OID NOT NULL,
                        l1_tx_id            BYTEA NOT NULL,
                        l1_start_hash       BYTEA NOT NULL,
                        l1_end_hash         BYTEA NOT NULL,
                        l2_start_height     OID NOT NULL,
                        l2_end_height       OID NOT NULL,
                        merkle_root         BYTEA NOT NULL,
                        status              VARCHAR(15) NOT NULL,
                        UNIQUE (l2_start_height, l2_end_height),
                        UNIQUE (l1_start_height, l1_end_height),
                        UNIQUE (l1_start_hash, l1_end_hash)
                    );
                    """
                )

                idx1 = "CREATE INDEX IF NOT EXISTS idx_l2_end_height ON sequencer_commitments(l2_end_height);";
                idx2 = "CREATE INDEX IF NOT EXISTS idx_l1_end_height ON sequencer_commitments(l1_end_height);";
                idx3 = "CREATE INDEX IF NOT EXISTS idx_l1_end_hash ON sequencer_commitments(l1_end_hash);";
                try:
                    await cur.execute(idx1)
                    await cur.execute(idx2)
                    await cur.execute(idx3)
                except Exception as e:
                    pass

                rand_data = random_sequencer_commitments()
                try:
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
                except Exception as e:
                    print(e)
                    pass

