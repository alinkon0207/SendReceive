use std::mem::size_of;
use anchor_lang::prelude::*;
use solana_program::{program::invoke, program::invoke_signed, system_instruction};
use solana_program::pubkey::Pubkey;
use anchor_spl::{
    token::{self, Mint, Token, TokenAccount, Transfer},
    associated_token::AssociatedToken
};

declare_id!("DpUqnXt9jeVTFupvGwkNsV7Nbb9hv5UTi6SDpLVrPh5i");

const MAX_SEND_TIERS: usize = 10;
const MAX_PAY_TIERS: usize = 10;
const MAX_REFERRAL_TIERS: usize = 10;
const FEE_DIVIDER: u64 = 100_000;

#[program]
pub mod solana_vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, authority: Pubkey) -> Result<()> {
        let accts = ctx.accounts;
        let contract_state = &mut accts.contract_state;
        contract_state.authority = authority;
        contract_state.contract_enabled = true;
        contract_state.send_fees[0] = 250_000;
        contract_state.pay_fees[0] = 500_000;
        contract_state.pay_tax_factors[0] = 1_000;
        contract_state.referral_fee_factors[0] = 2_500;
        contract_state.referral_fee_factors[1] = 5_000;
        contract_state.referral_fee_factors[2] = 7_500;
        contract_state.referral_fee_factors[3] = 10_000;

        let rent = Rent::default();
        let required_lamports = rent
            .minimum_balance(0)
            .max(1)
            .saturating_sub(accts.vault.to_account_info().lamports());
        msg!("required lamports = {:?}", required_lamports);
        invoke(
            &system_instruction::transfer(
                &accts.authority.key(),
                &accts.vault.key(),
                required_lamports,
            ),
            &[
                accts.authority.to_account_info().clone(),
                accts.vault.clone(),
                accts.system_program.to_account_info().clone(),
            ],
        )?;

        Ok(())
    }

    pub fn init_user_state(ctx: Context<InitUserState>) -> Result<()> {
        ctx.accounts.user_state.user = ctx.accounts.authority.key();
        Ok(())
    }

    pub fn send_sol(ctx: Context<SendSol>, amount:u64) -> Result<()> {
        let accts = ctx.accounts;
        require!(accts.contract_state.contract_enabled, ContractError::NotEnabled);

        let contract_state = &mut accts.contract_state;
        let from = &accts.from;
        let to = &accts.to;
        let refer = &accts.refer;

        let mut send_fee = contract_state.send_fees[accts.user_state.send_tier as usize];

        invoke(
            &system_instruction::transfer(&from.key(), &to.key(), amount),
            &[
                from.to_account_info().clone(),
                to.to_account_info().clone(),
                accts.system_program.to_account_info().clone(),
            ],
        )?;

        if refer.key().ne(&Pubkey::default()) {
            let referral_fee_factor = contract_state.referral_fee_factors[accts.user_state.refer_tier as usize];
            let refer_fee = send_fee * referral_fee_factor / FEE_DIVIDER;

            invoke(
                &system_instruction::transfer(&from.key(), &refer.key(), refer_fee),
                &[
                    from.to_account_info().clone(),
                    refer.to_account_info().clone(),
                    accts.system_program.to_account_info().clone(),
                ],
            )?;

            emit!(EventReferralPayout {
                refer: refer.key(),
                sender: from.key(),
                refer_fee: refer_fee,
                refer_tax: 0,
            });

            send_fee = send_fee - refer_fee * 2;
        }

        invoke(
            &system_instruction::transfer(&from.key(), &accts.vault.key(), send_fee),
            &[
                from.to_account_info().clone(),
                accts.vault.clone(),
                accts.system_program.to_account_info().clone(),
            ],
        )?;

        contract_state.tx_count = contract_state.tx_count.checked_add(1).ok_or(ContractError::TxCountOverflow)?;
        
        emit!(EventSendTransaction {
            tx_count: contract_state.tx_count,
            tx_type: TxType::SendSol,
            from: from.key(),
            to: to.key(),
            amount: amount,
            token: Pubkey::default(),
            refer: refer.key(),
        });

        Ok(())
    }

    
    pub fn send_token(ctx: Context<SendToken>, amount:u64) -> Result<()> {
        let accts = ctx.accounts;
        require!(accts.contract_state.contract_enabled, ContractError::NotEnabled);

        let contract_state = &mut accts.contract_state;
        let from = &accts.from;
        let to = &accts.to;
        let refer = &accts.refer;

        let mut send_fee = contract_state.send_fees[accts.user_state.send_tier as usize];
        
        let cpi_cxt = CpiContext::new(
            accts.token_program.to_account_info(),
            Transfer {
                from: accts.ata_from.to_account_info(),
                to: accts.ata_to.to_account_info(),
                authority: accts.vault.to_account_info(),
            },
        );

        token::transfer(cpi_cxt, amount as u64)?;

        if refer.key().ne(&Pubkey::default()) {
            let referral_fee_factor = contract_state.referral_fee_factors[accts.user_state.refer_tier as usize];
            let refer_fee = send_fee * referral_fee_factor / FEE_DIVIDER;


            invoke(
                &system_instruction::transfer(&from.key(), &refer.key(), refer_fee),
                &[
                    from.to_account_info().clone(),
                    refer.to_account_info().clone(),
                    accts.system_program.to_account_info().clone(),
                ],
            )?;

            emit!(EventReferralPayout {
                refer: refer.key(),
                sender: from.key(),
                refer_fee: refer_fee,
                refer_tax: 0,
            });

            send_fee = send_fee - refer_fee * 2;
        }

        invoke(
            &system_instruction::transfer(&from.key(), &accts.vault.key(), send_fee),
            &[
                from.to_account_info().clone(),
                accts.vault.clone(),
                accts.system_program.to_account_info().clone(),
            ],
        )?;

        contract_state.tx_count = contract_state.tx_count.checked_add(1).ok_or(ContractError::TxCountOverflow)?;
        
        emit!(EventSendTransaction {
            tx_count: contract_state.tx_count,
            tx_type: TxType::SendSol,
            from: from.key(),
            to: to.key(),
            amount: amount,
            token: Pubkey::default(),
            refer: refer.key(),
        });

        Ok(())
    }

    pub fn pay_sol(ctx: Context<PaySol>, amount:u64) -> Result<()> {
        let accts = ctx.accounts;
        require!(accts.contract_state.contract_enabled, ContractError::NotEnabled);
    
        let contract_state = &mut accts.contract_state;
        let from = &accts.from;
        let to = &accts.to;
        let refer = &accts.refer;
    
        let mut pay_fee = contract_state.pay_fees[accts.user_state.pay_tier as usize];
        let pay_tax = contract_state.pay_tax_factors[accts.user_state.pay_tier as usize];
    
        invoke(
            &system_instruction::transfer(&from.key(), &to.key(), amount - pay_tax),
            &[
                from.to_account_info().clone(),
                to.to_account_info().clone(),
                accts.system_program.to_account_info().clone(),
            ],
        )?;
    
        if refer.key().ne(&Pubkey::default()) {
            let referral_fee_factor = contract_state.referral_fee_factors[accts.user_state.refer_tier as usize];
            let refer_fee = pay_fee * referral_fee_factor / FEE_DIVIDER;
            let refer_tax = pay_tax * referral_fee_factor / FEE_DIVIDER;
    
            invoke(
                &system_instruction::transfer(&from.key(), &refer.key(), refer_fee + refer_tax),
                &[
                    from.to_account_info().clone(),
                    refer.to_account_info().clone(),
                    accts.system_program.to_account_info().clone(),
                ],
            )?;
    
            emit!(EventReferralPayout {
                refer: refer.key(),
                sender: from.key(),
                refer_fee: refer_fee,
                refer_tax: refer_tax,
            });
    
            pay_fee = pay_fee - (refer_fee + refer_tax) * 2;
        }
    
        invoke(
            &system_instruction::transfer(&from.key(), &accts.vault.key(), pay_fee),
            &[
                from.to_account_info().clone(),
                accts.vault.clone(),
                accts.system_program.to_account_info().clone(),
            ],
        )?;
    
        contract_state.tx_count = contract_state.tx_count.checked_add(1).ok_or(ContractError::TxCountOverflow)?;
        
        emit!(EventSendTransaction {
            tx_count: contract_state.tx_count,
            tx_type: TxType::PaySol,
            from: from.key(),
            to: to.key(),
            amount: amount,
            token: Pubkey::default(),
            refer: refer.key(),
        });
    
        Ok(())
    }

    pub fn pay_token(ctx: Context<PayToken>, amount:u64) -> Result<()> {
        let accts = ctx.accounts;
        require!(accts.contract_state.contract_enabled, ContractError::NotEnabled);
    
        let contract_state = &mut accts.contract_state;
        let from = &accts.from;
        let to = &accts.to;
        let refer = &accts.refer;
    
        let mut pay_fee = contract_state.pay_fees[accts.user_state.pay_tier as usize];
        let mut pay_tax = contract_state.pay_tax_factors[accts.user_state.pay_tier as usize];
    
        let mut cpi_cxt = CpiContext::new(
            accts.token_program.to_account_info(),
            Transfer {
                from: accts.ata_from.to_account_info(),
                to: accts.ata_vault.to_account_info(),
                authority: accts.vault.to_account_info(),
            },
        );
        token::transfer(cpi_cxt, pay_tax as u64)?;
    
        if refer.key().ne(&Pubkey::default()) {
            let referral_fee_factor = contract_state.referral_fee_factors[accts.user_state.refer_tier as usize];
            let refer_fee = pay_fee * referral_fee_factor / FEE_DIVIDER;
            let refer_tax = pay_tax * referral_fee_factor / FEE_DIVIDER;
    
            invoke(
                &system_instruction::transfer(&from.key(), &refer.key(), refer_fee + refer_tax),
                &[
                    from.to_account_info().clone(),
                    refer.to_account_info().clone(),
                    accts.system_program.to_account_info().clone(),
                ],
            )?;

            cpi_cxt = CpiContext::new(
                accts.token_program.to_account_info(),
                Transfer {
                    from: accts.ata_from.to_account_info(),
                    to: accts.ata_refer.to_account_info(),
                    authority: accts.vault.to_account_info(),
                },
            );
            token::transfer(cpi_cxt, refer_tax as u64)?;
    
            emit!(EventReferralPayout {
                refer: refer.key(),
                sender: from.key(),
                refer_fee: refer_fee,
                refer_tax: refer_tax,
            });
    
            pay_fee = pay_fee - (refer_fee + refer_tax) * 2;
            pay_tax = pay_tax + refer_tax;
        }
    
        invoke(
            &system_instruction::transfer(&from.key(), &accts.vault.key(), pay_fee),
            &[
                from.to_account_info().clone(),
                accts.vault.clone(),
                accts.system_program.to_account_info().clone(),
            ],
        )?;

        cpi_cxt = CpiContext::new(
            accts.token_program.to_account_info(),
            Transfer {
                from: accts.ata_from.to_account_info(),
                to: accts.ata_vault.to_account_info(),
                authority: accts.vault.to_account_info(),
            },
        );
        token::transfer(cpi_cxt, amount - pay_tax as u64)?;
    
        contract_state.tx_count = contract_state.tx_count.checked_add(1).ok_or(ContractError::TxCountOverflow)?;
        
        emit!(EventSendTransaction {
            tx_count: contract_state.tx_count,
            tx_type: TxType::PaySol,
            from: from.key(),
            to: to.key(),
            amount: amount,
            token: Pubkey::default(),
            refer: refer.key(),
        });
    
        Ok(())
    }

    pub fn set_contract_enabled(ctx: Context<SetContractEnabled>, contract_enabled: bool) -> Result<()> {
        require!(ctx.accounts.authority.key() == ctx.accounts.contract_state.authority, ContractError::Unauthorized);
        
        let contract_state = &mut ctx.accounts.contract_state;
        contract_state.contract_enabled = contract_enabled;
    
        emit!(EventSetContractEnabled {
            contract_enabled,
        });
    
        Ok(())
    }

    pub fn set_send_tier(ctx: Context<SetSendTier>, user_pubkey: Pubkey, send_tier: u64) -> Result<()> {
        require!(ctx.accounts.authority.key() == ctx.accounts.contract_state.authority, ContractError::Unauthorized);
    
        let user_state = &mut ctx.accounts.user_state;
        user_state.send_tier = send_tier;
    
        emit!(EventSetSendTier {
            user: user_pubkey,
            send_tier,
        });
    
        Ok(())
    }

    pub fn set_pay_tier(ctx: Context<SetPayTier>, user_pubkey: Pubkey, pay_tier: u64) -> Result<()> {
        require!(ctx.accounts.authority.key() == ctx.accounts.contract_state.authority, ContractError::Unauthorized);
    
        let user_state = &mut ctx.accounts.user_state;
        user_state.pay_tier = pay_tier;
    
        emit!(EventSetPayTier {
            user: user_pubkey,
            pay_tier,
        });
    
        Ok(())
    }

    pub fn set_refer_tier(ctx: Context<SetReferTier>, user_pubkey: Pubkey, refer_tier: u64) -> Result<()> {
        require!(ctx.accounts.authority.key() == ctx.accounts.contract_state.authority, ContractError::Unauthorized);
    
        let user_state = &mut ctx.accounts.user_state;
        user_state.refer_tier = refer_tier;
    
        emit!(EventSetReferTier {
            user: user_pubkey,
            refer_tier,
        });
    
        Ok(())
    }

    pub fn set_send_fee(ctx: Context<SetSendFee>, send_tier: u64, send_fee: u64) -> Result<()> {
        require!(ctx.accounts.authority.key() == ctx.accounts.contract_state.authority, ContractError::Unauthorized);
        require!(send_tier < MAX_SEND_TIERS as u64, ContractError::InvalidTier);
    
        let contract_state = &mut ctx.accounts.contract_state;
        contract_state.send_fees[send_tier as usize] = send_fee;
    
        emit!(EventSetSendFee {
            send_tier,
            send_fee,
        });
    
        Ok(())
    }

    pub fn set_pay_fee(ctx: Context<SetPayFee>, pay_tier: u64, pay_fee: u64) -> Result<()> {
        require!(ctx.accounts.authority.key() == ctx.accounts.contract_state.authority, ContractError::Unauthorized);
        require!(pay_tier < MAX_PAY_TIERS as u64, ContractError::InvalidTier);
    
        let contract_state = &mut ctx.accounts.contract_state;
        contract_state.pay_fees[pay_tier as usize] = pay_fee;
    
        emit!(EventSetPayFee {
            pay_tier,
            pay_fee,
        });
    
        Ok(())
    }

    pub fn set_pay_tax_factor(ctx: Context<SetPayTaxFactor>, pay_tier: u64, pay_tax_factor: u64) -> Result<()> {
        require!(ctx.accounts.authority.key() == ctx.accounts.contract_state.authority, ContractError::Unauthorized);
        require!(pay_tier < MAX_PAY_TIERS as u64, ContractError::InvalidTier);
    
        let contract_state = &mut ctx.accounts.contract_state;
        contract_state.pay_tax_factors[pay_tier as usize] = pay_tax_factor;
    
        emit!(EventSetPayTaxFactor {
            pay_tier,
            pay_tax_factor,
        });
    
        Ok(())
    }

    pub fn set_refer_fee_factor(ctx: Context<SetReferFeeFactor>, refer_tier: u64, refer_fee_factor: u64) -> Result<()> {
        require!(ctx.accounts.authority.key() == ctx.accounts.contract_state.authority, ContractError::Unauthorized);
        require!(refer_tier < MAX_REFERRAL_TIERS as u64, ContractError::InvalidTier);
    
        let contract_state = &mut ctx.accounts.contract_state;
        contract_state.referral_fee_factors[refer_tier as usize] = refer_fee_factor;
    
        emit!(EventSetReferFeeFactor {
            refer_tier,
            refer_fee_factor,
        });
    
        Ok(())
    }

    pub fn claim_sol_fees(ctx: Context<ClaimSolFees>) -> Result<()> {
        let accts = ctx.accounts;

        require!(accts.authority.key() == accts.contract_state.authority, ContractError::Unauthorized);
        
        let bump = ctx.bumps.vault;
        let claim_amount = accts.vault.to_account_info().lamports();

        invoke_signed(
            &system_instruction::transfer(&accts.vault.key(), &accts.claim.key(), claim_amount),
            &[
                accts.vault.to_account_info().clone(),
                accts.claim.clone(),
                accts.system_program.to_account_info().clone(),
            ],
            &[&[b"VAULT", &[bump]]],
        )?;

        emit!(EventClaimedSolFees {
            claim_address: accts.claim.key(),
            claim_amount,
        });

        Ok(())
    }

    pub fn claim_token_fees(ctx: Context<ClaimTokenFees>, claim_address: Pubkey, token_mint: Pubkey) -> Result<()> {
        let accts = ctx.accounts;
    
        require!(accts.authority.key() == accts.contract_state.authority, ContractError::Unauthorized);
        require!(claim_address != Pubkey::default(), ContractError::InvalidAddress);
    
        let bump = ctx.bumps.vault;
        let seed: &[&[&[u8]]] = &[&[b"VAULT", &[bump]]];
        let contract_token_account = &accts.token;
        let claim_amount = contract_token_account.amount;
    
        let cpi_accounts = Transfer {
            from: contract_token_account.to_account_info(),
            to: accts.ata_claim.to_account_info(),
            authority: accts.vault.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(accts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx.with_signer(seed), claim_amount)?;
    
        emit!(EventClaimedTokenFees {
            claim_address,
            token: token_mint,
            claim_amount,
        });
    
        Ok(())
    }    
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = user,
        space = 8 + 40,
        seeds = [b"STATE"],
        bump
    )]
    pub contract_state: Account<'info, ContractState>,

    #[account(
        mut,
        seeds = [b"VAULT"],
        bump
    )]
    /// CHECK: this should be set by admin
    pub vault: AccountInfo<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>
}

#[derive(Accounts)]
pub struct InitUserState<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        seeds = [b"USER_STATE", authority.key().as_ref()],
        bump,
        payer = authority,
        space = size_of::<UserState>() + 8
    )]
    pub user_state: Account<'info, UserState>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>
}

#[derive(Accounts)]
#[instruction(x: u64)]
pub struct SendSol<'info> {
    #[account(
        mut,
        seeds = [b"STATE"],
        bump
    )]
    pub contract_state: Account<'info, ContractState>,

    #[account(
        mut,
        seeds = [b"USER_STATE", from.key().as_ref()],
        bump
    )]
    pub user_state: Account<'info, UserState>,

    #[account(
        mut,
        seeds = [b"USER_STATE", refer.key().as_ref()],
        bump
    )]
    pub refer_state: Account<'info, UserState>,

    #[account(
        mut,
        seeds = [b"VAULT"],
        bump
    )]
    /// CHECK: this should be set by admin
    pub vault: AccountInfo<'info>,

    #[account(mut)]
    pub from: Signer<'info>,

    #[account(mut)]
    /// CHECK: this should be set by admin
    pub to: AccountInfo<'info>,

    #[account(mut)]
    /// CHECK: this should be set by admin
    pub refer: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(x: u64)]
pub struct SendToken<'info> {
    #[account(
        mut,
        seeds = [b"STATE"],
        bump
    )]
    pub contract_state: Account<'info, ContractState>,

    #[account(
        mut,
        seeds = [b"USER_STATE", from.key().as_ref()],
        bump
    )]
    pub user_state: Account<'info, UserState>,

    #[account(
        mut,
        seeds = [b"USER_STATE", refer.key().as_ref()],
        bump
    )]
    pub refer_state: Account<'info, UserState>,

    #[account(
        mut,
        seeds = [b"VAULT"],
        bump
    )]
    /// CHECK: this should be set by admin
    pub vault: AccountInfo<'info>,

    #[account(mut)]
    pub token: Box<Account<'info, Mint>>,

    #[account(
        mut,
        associated_token::mint = token,
        associated_token::authority = from,
    )]
    pub ata_from: Box<Account<'info, TokenAccount>>,
    
    #[account(
        init_if_needed,
        payer = from,
        associated_token::mint = token,
        associated_token::authority = from,
    )]
    pub ata_to: Box<Account<'info, TokenAccount>>,

    #[account(
        init_if_needed,
        payer = from,
        associated_token::mint = token,
        associated_token::authority = vault,
    )]
    pub ata_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        init_if_needed,
        payer = from,
        associated_token::mint = token,
        associated_token::authority = refer,
    )]
    pub ata_refer: Box<Account<'info, TokenAccount>>,

    #[account(mut)]
    pub from: Signer<'info>,

    #[account(mut)]
    /// CHECK: this should be set by admin
    pub to: AccountInfo<'info>,

    #[account(mut)]
    /// CHECK: this should be set by admin
    pub refer: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}


#[derive(Accounts)]
#[instruction(x: u64)]
pub struct PaySol<'info> {
    #[account(
        mut,
        seeds = [b"STATE"],
        bump
    )]
    pub contract_state: Account<'info, ContractState>,

    #[account(
        mut,
        seeds = [b"USER_STATE", from.key().as_ref()],
        bump
    )]
    pub user_state: Account<'info, UserState>,

    #[account(
        mut,
        seeds = [b"USER_STATE", refer.key().as_ref()],
        bump
    )]
    pub refer_state: Account<'info, UserState>,

    #[account(
        mut,
        seeds = [b"VAULT"],
        bump
    )]
    /// CHECK: this should be set by admin
    pub vault: AccountInfo<'info>,

    #[account(mut)]
    pub from: Signer<'info>,

    #[account(mut)]
    /// CHECK: this should be set by admin
    pub to: AccountInfo<'info>,

    #[account(mut)]
    /// CHECK: this should be set by admin
    pub refer: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(x: u64)]
pub struct PayToken<'info> {
    #[account(
        mut,
        seeds = [b"STATE"],
        bump
    )]
    pub contract_state: Account<'info, ContractState>,

    #[account(
        mut,
        seeds = [b"USER_STATE", from.key().as_ref()],
        bump
    )]
    pub user_state: Account<'info, UserState>,

    #[account(
        mut,
        seeds = [b"USER_STATE", refer.key().as_ref()],
        bump
    )]
    pub refer_state: Account<'info, UserState>,

    #[account(
        mut,
        seeds = [b"VAULT"],
        bump
    )]
    /// CHECK: this should be set by admin
    pub vault: AccountInfo<'info>,

    #[account(mut)]
    pub token: Box<Account<'info, Mint>>,

    #[account(
        mut,
        associated_token::mint = token,
        associated_token::authority = from,
    )]
    pub ata_from: Box<Account<'info, TokenAccount>>,
    
    #[account(
        init_if_needed,
        payer = from,
        associated_token::mint = token,
        associated_token::authority = from,
    )]
    pub ata_to: Box<Account<'info, TokenAccount>>,

    #[account(
        init_if_needed,
        payer = from,
        associated_token::mint = token,
        associated_token::authority = vault,
    )]
    pub ata_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        init_if_needed,
        payer = from,
        associated_token::mint = token,
        associated_token::authority = refer,
    )]
    pub ata_refer: Box<Account<'info, TokenAccount>>,

    #[account(mut)]
    pub from: Signer<'info>,

    #[account(mut)]
    /// CHECK: this should be set by admin
    pub to: AccountInfo<'info>,

    #[account(mut)]
    /// CHECK: this should be set by admin
    pub refer: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}

#[derive(Accounts)]
pub struct SetContractEnabled<'info> {
    #[account(
        mut,
        seeds = [b"STATE"],
        bump,
        has_one = authority
    )]
    pub contract_state: Account<'info, ContractState>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(user_pubkey: Pubkey, y: u64)]
pub struct SetSendTier<'info> {
    #[account(
        mut,
        seeds = [b"STATE"],
        bump,
        has_one = authority
    )]
    pub contract_state: Account<'info, ContractState>,

    #[account(
        mut,
        seeds = [b"USER_STATE", user_pubkey.as_ref()],
        bump
    )]
    pub user_state: Account<'info, UserState>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(user_pubkey: Pubkey, y: u64)]
pub struct SetPayTier<'info> {
    #[account(
        mut,
        seeds = [b"STATE"],
        bump,
        has_one = authority
    )]
    pub contract_state: Account<'info, ContractState>,

    #[account(
        mut,
        seeds = [b"USER_STATE", user_pubkey.as_ref()],
        bump
    )]
    pub user_state: Account<'info, UserState>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(refer_pubkey: Pubkey, y: u64)]
pub struct SetReferTier<'info> {
    #[account(
        mut,
        seeds = [b"STATE"],
        bump,
        has_one = authority
    )]
    pub contract_state: Account<'info, ContractState>,

    #[account(
        mut,
        seeds = [b"USER_STATE", refer_pubkey.as_ref()],
        bump
    )]
    pub user_state: Account<'info, UserState>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetSendFee<'info> {
    #[account(
        mut,
        seeds = [b"STATE"],
        bump,
        has_one = authority
    )]
    pub contract_state: Account<'info, ContractState>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetPayFee<'info> {
    #[account(
        mut,
        seeds = [b"STATE"],
        bump,
        has_one = authority
    )]
    pub contract_state: Account<'info, ContractState>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetPayTaxFactor<'info> {
    #[account(
        mut,
        seeds = [b"STATE"],
        bump,
        has_one = authority
    )]
    pub contract_state: Account<'info, ContractState>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetReferFeeFactor<'info> {
    #[account(
        mut,
        seeds = [b"STATE"],
        bump,
        has_one = authority
    )]
    pub contract_state: Account<'info, ContractState>,

    #[account(mut)]
    pub authority: Signer<'info>,
}


#[derive(Accounts)]
pub struct ClaimSolFees<'info> {
    #[account(
        mut,
        seeds = [b"STATE"],
        bump,
        has_one = authority
    )]
    pub contract_state: Account<'info, ContractState>,

    #[account(
        mut,
        seeds = [b"VAULT"],
        bump
    )]
    /// CHECK: this should be set by admin
    pub vault: AccountInfo<'info>,

    #[account(mut)]
    /// CHECK: This is a system account for receiving SOL
    pub claim: AccountInfo<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(claim_address: Pubkey, token_mint: Pubkey)]
pub struct ClaimTokenFees<'info> {
    #[account(
        mut,
        seeds = [b"STATE"],
        bump,
        has_one = authority
    )]
    pub contract_state: Account<'info, ContractState>,

    #[account(
        mut,
        seeds = [b"VAULT"],
        bump
    )]
    /// CHECK: this should be set by admin
    pub vault: AccountInfo<'info>,

    #[account(
        mut,
        associated_token::mint = token_mint,
        associated_token::authority = vault,
    )]
    pub token: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        associated_token::mint = token_mint,
        associated_token::authority = claim_address,
    )]
    pub ata_claim: Box<Account<'info, TokenAccount>>,

    #[account(mut)]
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
    pub system_program: Program<'info, System>,
    pub associated_token_program: Program<'info, AssociatedToken>,
}


#[account]
#[derive(Default)]
pub struct ContractState {
    authority: Pubkey,
    contract_enabled: bool,
    tx_count: u64,
    send_fees: [u64; MAX_SEND_TIERS],
    pay_fees: [u64; MAX_PAY_TIERS],
    pay_tax_factors: [u64; MAX_PAY_TIERS],
    referral_fee_factors: [u64; MAX_REFERRAL_TIERS],
}

#[account]
#[derive(Default)]
pub struct UserState {
    user: Pubkey,
    send_tier: u64,
    pay_tier: u64,
    refer_tier: u64
}

#[event]
pub struct EventReferralPayout {
    refer: Pubkey,
    sender: Pubkey,
    refer_fee: u64,
    refer_tax: u64,
}

#[event]
pub struct EventSendTransaction {
    tx_count: u64,
    tx_type: TxType,
    from: Pubkey,
    to: Pubkey,
    amount: u64,
    token: Pubkey,
    refer: Pubkey,
}

#[event]
pub struct EventSetContractEnabled {
    contract_enabled: bool,
}

#[event]
pub struct EventSetSendTier {
    user: Pubkey,
    send_tier: u64,
}

#[event]
pub struct EventSetPayTier {
    user: Pubkey,
    pay_tier: u64,
}

#[event]
pub struct EventSetReferTier {
    user: Pubkey,
    refer_tier: u64,
}

#[event]
pub struct EventSetSendFee {
    send_tier: u64,
    send_fee: u64,
}

#[event]
pub struct EventSetPayFee {
    pay_tier: u64,
    pay_fee: u64,
}

#[event]
pub struct EventSetPayTaxFactor {
    pay_tier: u64,
    pay_tax_factor: u64,
}

#[event]
pub struct EventSetReferFeeFactor {
    refer_tier: u64,
    refer_fee_factor: u64,
}

#[event]
pub struct EventClaimedSolFees {
    claim_address: Pubkey,
    claim_amount: u64,
}

#[event]
pub struct EventClaimedTokenFees {
    claim_address: Pubkey,
    token: Pubkey,
    claim_amount: u64,
}

#[error_code]
pub enum ContractError {
    #[msg("Author should be owner")]
    Unauthorized,
    #[msg("Contract should be enabled")]
    NotEnabled,
    #[msg("Tx count overflow")]
    TxCountOverflow,
    #[msg("Limited tier")]
    InvalidTier,
    #[msg("Wrong address")]
    InvalidAddress
}

#[derive(
    AnchorSerialize,
    AnchorDeserialize,
    Clone,
    PartialEq,
    Eq,
)]
pub enum TxType {
    SendSol = 0,
    SendToken,
    PaySol,
    PayToken,
}