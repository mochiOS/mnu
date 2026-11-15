use spin::Mutex;

type IrqHandler = extern "C" fn(u8);

static IRQ_HANDLERS: Mutex<[Option<IrqHandler>; 16]> = Mutex::new([None; 16]);

pub fn register_handler(irq: u8, handler: IrqHandler) -> i32 {
    #[cfg(target_arch = "aarch64")]
    {
        // This legacy API addresses PIC lines, not assigned GIC resources.
        // Native devices use the mDriver/EL2 ownership and event transport.
        let _ = (irq, handler);
        return -95;
    }
    #[cfg(target_arch = "x86_64")]
    {
        if irq >= 16 || irq == 0 || irq == 1 || irq == 2 || irq == 12 {
            return -22;
        }
        let mut handlers = IRQ_HANDLERS.lock();
        handlers[irq as usize] = Some(handler);
        if super::pic::unmask_irq(irq) {
            0
        } else {
            -22
        }
    }
}

pub fn dispatch(irq: u8) {
    let handler = {
        let handlers = IRQ_HANDLERS.lock();
        handlers[irq as usize]
    };
    if let Some(handler) = handler {
        handler(irq);
    }
}
