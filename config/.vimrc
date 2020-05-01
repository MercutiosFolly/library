" For Cscope functionality, please see:
" http://cscope.sourceforge.net/cscope_vim_tutorial.html
 
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

" PYTHON whitespace
autocmd Filetype python setlocal expandtab
  \ | setlocal shiftround
  \ | setlocal textwidth=79
  \ | setlocal shiftwidth=4
  \ | setlocal tabstop=4
  \ | setlocal softtabstop=4
  \ | setlocal autoindent
let python_highlight_all = 1

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
