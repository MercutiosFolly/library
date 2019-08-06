" Default Colorscheme
colorscheme slate

" No vi Compatibility
set nocompatible

filetype off

" Load Plugins
execute pathogen#infect()
syntax on
filetype plugin indent on

" NERDTree
autocmd StdinReadPre * let s:std_in=1
autocmd VimEnter * if argc() == 0 && !exists("s:std_in") | NERDTree | endif

" Numbering
set number

" File Info
set ruler

" Turn off Annoying Beeping
set visualbell

" Whitespace Management
set wrap
set expandtab
set shiftwidth=2
set softtabstop=2

" Search
set hlsearch
set ignorecase
set smartcase
"set incsearch


" Visualizing
set showmode
set showcmd
set showmatch

" Setup swap/backup
set backupdir=~/.vim/.backup
set directory=~/.vim/.swp
